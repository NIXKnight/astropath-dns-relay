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

"""Startup configuration fail-fast (SPEC §11.3, LOW-5, T-M6-10).

Every precondition that can be checked cheaply is checked *before* the process
binds its readiness — a misconfigured relay must crash loudly at boot, never
half-serve.

:func:`validate_kek` validates the credential KEK up front (the KEK is always
required — it decrypts the DB-stored provider/TSIG/HE secrets). Then, for the
two-plane composition (:func:`astropath.main.serve`), :func:`validate_db_startup`
runs the full SPEC §11.3 checklist before readiness is bound: the SPA-directory
presence policy, database reachability (a bounded connect smoke test), the schema
being at the Alembic head, every ``Backend.type`` resolving in the provider
registry, and every ``TsigKey.algorithm`` mapping.

All failures raise :class:`StartupError` with a message that names the offending
revision / provider / algorithm / key **position** — never a DSN, key, or secret
value.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from sqlalchemy import Connection
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlmodel import select

from astropath.crypto import Kek, KekError
from astropath.data_plane.tsig import UnknownAlgorithm, algorithm_from_text
from astropath.db import Database
from astropath.models import Backend, TsigKey
from astropath.providers.base import UnknownProvider, get_provider
from astropath.settings import Settings

__all__ = ["StartupError", "validate_db_startup", "validate_kek"]


class StartupError(RuntimeError):
    """A startup precondition failed; the process must not bind readiness.

    Messages are safe to log: they identify configuration by revision, provider,
    algorithm, or key *position*, and never carry a decrypted secret.
    """


def validate_kek(kek_keylist: str | None) -> Kek:
    """Validate the credential KEK and return it (SPEC §7 / §11.3).

    The KEK is always required: it decrypts the DB-stored provider configs, TSIG
    secrets, and HE per-record keys. Raises :class:`StartupError` on an unset or
    malformed keylist — the message names the offending key **position**, never
    the raw key material.
    """
    if not kek_keylist:
        raise StartupError(
            "credential KEK is not configured (set ASTROPATH_CREDENTIAL_KEK)"
        )
    try:
        return Kek.from_keylist(kek_keylist)
    except KekError as exc:
        # KekError already redacts to key position; never echo the raw keylist.
        raise StartupError(f"invalid credential KEK: {exc}") from exc


def _alembic_head(alembic_ini: str) -> str | None:
    """The head revision id per the Alembic scripts (not a secret).

    Resolving the script directory needs ``alembic.ini`` plus the ``alembic/``
    migrations tree at that ini's location; the runtime image bakes both in
    (Dockerfile). When either is absent — or ``script_location`` otherwise fails
    to resolve — Alembic raises :class:`~alembic.util.exc.CommandError` ("No
    'script_location' key found in configuration" for a missing/empty ini, "Path
    doesn't exist" for a missing scripts dir); every config-missing mode surfaces
    as that one type. ``CommandError`` is not a :class:`StartupError`, so ``main()``
    would let it escape as an uncaught traceback (exit 1, crash-loop) instead of a
    clean fail-fast. Re-raise it as :class:`StartupError` — which ``main()`` maps
    to exit 2 — with a secret-free, actionable message (the wrapped text names only
    a config key / filesystem path, never a DSN or secret).
    """
    from alembic.config import Config
    from alembic.script import ScriptDirectory
    from alembic.util.exc import CommandError

    try:
        return ScriptDirectory.from_config(Config(alembic_ini)).get_current_head()
    except CommandError as exc:
        raise StartupError(
            f"alembic migrations are not resolvable from {alembic_ini!r} ({exc}); "
            "the runtime image must ship alembic.ini and the alembic/ directory"
        ) from exc


async def _db_current_revision(engine: AsyncEngine) -> str | None:
    """The revision stamped in the database's ``alembic_version`` (or ``None``)."""
    from alembic.migration import MigrationContext

    def _read(sync_conn: Connection) -> str | None:
        return MigrationContext.configure(sync_conn).get_current_revision()

    async with engine.connect() as conn:
        return await conn.run_sync(_read)


async def validate_db_startup(
    database: Database,
    settings: Settings,
    *,
    alembic_ini: str = "alembic.ini",
    connect_timeout: float = 5.0,
) -> None:
    """Fail-fast the DB-backed startup preconditions (SPEC §11.3, T-M6-10).

    Runs before readiness is bound, checking (in fail-fast order): the SPA
    directory presence policy, database reachability (bounded), the schema being
    at the Alembic head, provider-registry integrity for every ``Backend`` row,
    and the TSIG-algorithm mapping for every ``TsigKey`` row. Raises
    :class:`StartupError` with a message that never carries a DSN, key, or secret
    value — only revision ids, provider names, algorithm names, and the SPA path.
    """
    # 1. SPA directory presence policy — a cheap local check; fail before any IO.
    if settings.spa_dir is not None and not Path(settings.spa_dir).is_dir():
        raise StartupError(
            f"configured SPA directory does not exist: {settings.spa_dir}"
        )

    # 2. Database reachability — a bounded connect smoke test (no DSN in the error).
    try:
        await asyncio.wait_for(database.ping(), timeout=connect_timeout)
    except Exception as exc:  # noqa: BLE001 - normalize any driver error to a fail-fast
        raise StartupError(
            f"database is unreachable at startup ({type(exc).__name__}); "
            "check ASTROPATH_DATABASE_DSN"
        ) from exc

    # 3. Schema is at head — never serve on a stale or absent migration.
    head = _alembic_head(alembic_ini)
    current = await _db_current_revision(database.engine)
    if current != head:
        raise StartupError(
            f"database schema is not current (at revision {current!r}, expected "
            f"{head!r}); run 'alembic upgrade head'"
        )

    # 4. Provider-registry integrity + TSIG-algorithm mapping for every row.
    async with database.session() as session:
        backends = (await session.execute(select(Backend))).scalars().all()
        tsig_keys = (await session.execute(select(TsigKey))).scalars().all()
    for backend in backends:
        try:
            get_provider(backend.type)
        except UnknownProvider as exc:
            raise StartupError(
                f"backend {backend.name!r} references unknown provider "
                f"{backend.type!r}"
            ) from exc
    for key in tsig_keys:
        try:
            algorithm_from_text(key.algorithm)
        except UnknownAlgorithm as exc:
            raise StartupError(
                f"TSIG key {key.name!r} uses unsupported algorithm {key.algorithm!r}"
            ) from exc
