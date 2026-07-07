# SPDX-License-Identifier: GPL-3.0-or-later
#
# astropath-dns-relay — self-hosted ACME DNS-01 solver gateway.
# Copyright (C) 2026  Saad Ali
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""``astropath-migrate-bootstrap`` — M1 file → M2 database (T-M2-07, SPEC §16.3).

A one-shot command that reads the M1 ``astropath.bootstrap.yaml`` (TOML), applies
Alembic revision 1, and inserts ``TsigKey`` / ``Backend`` / ``Domain`` rows whose
secrets are re-encrypted under the **same** KEK. After migration the bootstrap
file can be retired: the data plane serves identically from the database, because
the DB-backed cache (:mod:`astropath.cache`) rebuilds the exact same
:class:`~astropath.bootstrap.BootstrapConfig` and reuses the shared
``build_data_plane`` runtime path.

One :class:`Backend` is created per distinct provider type (named after the type)
holding empty shared config — HE keeps no shared secret; the per-record dynamic
key is stored on each :class:`Domain` (HIGH-7). Fernet is non-deterministic, so
the ciphertext bytes differ from the file's, but the plaintext they protect is
unchanged — ciphertext *semantics* are preserved.

Secret discipline: decrypted secrets live in memory only; the command prints
counts, never secret values.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

from alembic import command
from alembic.config import Config
from sqlalchemy.ext.asyncio import AsyncSession

from astropath.bootstrap import BootstrapConfig, BootstrapError, load_bootstrap
from astropath.crypto import InvalidToken, Kek, KekError
from astropath.db import Database
from astropath.models import Backend
from astropath.store import SecretCodec, build_backend, build_domain, build_tsig_key

__all__ = [
    "MigrationCounts",
    "MigrationError",
    "apply_migrations",
    "insert_bootstrap_rows",
    "main",
    "migrate_bootstrap",
]


class MigrationError(RuntimeError):
    """A precondition failed; messages never carry a secret value."""


@dataclass(frozen=True)
class MigrationCounts:
    """How many rows the migration inserted (for the summary line)."""

    tsig_keys: int
    backends: int
    domains: int


async def insert_bootstrap_rows(
    session: AsyncSession, config: BootstrapConfig, kek: Kek
) -> MigrationCounts:
    """Insert TSIG/Backend/Domain rows from a decrypted config (SPEC §16.3).

    One backend per distinct provider type; each domain references it and carries
    the KEK-encrypted HE per-record key (or ``NULL`` for a keyless provider). The
    caller supplies the session; this commits it.
    """
    codec = SecretCodec(kek)

    for spec in config.tsig_keys:
        session.add(
            build_tsig_key(
                codec,
                name=spec.name,
                algorithm=spec.algorithm,
                secret_b64=spec.secret_b64,
            )
        )

    backends_by_type: dict[str, Backend] = {}
    for zone in config.zones:
        backend = backends_by_type.get(zone.provider)
        if backend is None:
            backend = build_backend(
                codec, name=zone.provider, backend_type=zone.provider, config={}
            )
            session.add(backend)
            await session.flush()  # assign backend.id before the domain references it
            backends_by_type[zone.provider] = backend
        assert backend.id is not None
        session.add(
            build_domain(
                codec,
                zone=zone.zone,
                backend_id=backend.id,
                record_name=zone.record_name,
                he_dynamic_key=zone.he_dynamic_key,
            )
        )

    await session.commit()
    return MigrationCounts(
        tsig_keys=len(config.tsig_keys),
        backends=len(backends_by_type),
        domains=len(config.zones),
    )


def apply_migrations(dsn: str, alembic_ini: str = "alembic.ini") -> None:
    """Run ``alembic upgrade head`` against ``dsn`` (env-injected in env.py)."""
    os.environ["ASTROPATH_DATABASE_DSN"] = dsn
    command.upgrade(Config(alembic_ini), "head")


async def migrate_bootstrap(
    *,
    dsn: str,
    bootstrap_path: str | Path,
    kek: Kek,
    alembic_ini: str = "alembic.ini",
) -> MigrationCounts:
    """Load the bootstrap file, apply revision 1, and insert the rows."""
    config = load_bootstrap(bootstrap_path, kek)
    apply_migrations(dsn, alembic_ini)
    db = Database.from_dsn(dsn)
    try:
        async with db.session() as session:
            return await insert_bootstrap_rows(session, config, kek)
    finally:
        await db.dispose()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="astropath-migrate-bootstrap",
        description="Migrate the M1 bootstrap file into the M2 database "
        "(apply revision 1 + insert TSIG/Backend/Domain rows).",
    )
    parser.add_argument(
        "--bootstrap",
        default=None,
        help="path to astropath.bootstrap.yaml (or set ASTROPATH_BOOTSTRAP_PATH)",
    )
    parser.add_argument("--alembic-config", default="alembic.ini")
    return parser


def _resolve_inputs(bootstrap: str | None) -> tuple[str, str, Kek]:
    dsn = os.environ.get("ASTROPATH_DATABASE_DSN")
    if not dsn:
        raise MigrationError("ASTROPATH_DATABASE_DSN is not set")
    kek_raw = os.environ.get("ASTROPATH_CREDENTIAL_KEK")
    if not kek_raw:
        raise MigrationError("ASTROPATH_CREDENTIAL_KEK is not set")
    path = bootstrap or os.environ.get("ASTROPATH_BOOTSTRAP_PATH")
    if not path:
        raise MigrationError(
            "bootstrap path not given (--bootstrap or ASTROPATH_BOOTSTRAP_PATH)"
        )
    if not Path(path).is_file():
        raise MigrationError(f"bootstrap file not found: {path}")
    try:
        kek = Kek.from_keylist(kek_raw)
    except KekError as exc:
        # KekError redacts to key position; never echo the raw keylist.
        raise MigrationError(f"invalid credential KEK: {exc}") from exc
    return dsn, path, kek


def main(argv: Sequence[str] | None = None, *, out: TextIO | None = None) -> int:
    """``python -m astropath.migrate_bootstrap`` entrypoint (SPEC §16.3)."""
    stream = out if out is not None else sys.stdout
    args = _build_parser().parse_args(argv)
    try:
        dsn, path, kek = _resolve_inputs(args.bootstrap)
        counts = asyncio.run(
            migrate_bootstrap(
                dsn=dsn,
                bootstrap_path=path,
                kek=kek,
                alembic_ini=args.alembic_config,
            )
        )
    except (MigrationError, BootstrapError) as exc:
        stream.write(f"# migration failed: {exc}\n")
        return 1
    except InvalidToken:
        stream.write(
            "# migration failed: bootstrap secrets do not decrypt under the KEK\n"
        )
        return 1

    stream.write(
        f"# migrated: {counts.tsig_keys} tsig keys, {counts.backends} backends, "
        f"{counts.domains} domains\n"
    )
    stream.write("# the bootstrap file may now be retired.\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
