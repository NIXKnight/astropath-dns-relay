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

"""DB-backed startup fail-fast tests (T-M6-10, SPEC §11.3).

The reachability + SPA-dir checks need no database; the schema/provider/algorithm
checks run against the shared ephemeral Postgres (Docker-gated via ``api_db``).
Throwaway values only; error messages must never carry a DSN or secret.
"""

from __future__ import annotations

import pytest
from tests.test_api_app import make_settings

from astropath import startup as startup_module
from astropath.db import Database
from astropath.models import Backend, TsigKey
from astropath.startup import StartupError, _alembic_head, validate_db_startup

# A DSN whose port has no listener — connection is refused fast (no Docker).
_DEAD_DSN = "postgresql+asyncpg://u:PLACEHOLDER_PW@127.0.0.1:1/db"


async def _insert(db: Database, *objs: object) -> None:
    async with db.session() as session:
        for obj in objs:
            session.add(obj)
        await session.commit()


# --------------------------------------------------------------------------- #
# No-Docker checks: SPA-directory policy and database reachability.
# --------------------------------------------------------------------------- #
async def test_missing_spa_dir_fails_fast() -> None:
    db = Database.from_dsn(_DEAD_DSN)  # lazy engine — the SPA check fails first
    try:
        with pytest.raises(StartupError, match="SPA directory"):
            await validate_db_startup(
                db, make_settings(spa_dir="/no/such/astropath/dir")
            )
    finally:
        await db.dispose()


async def test_unreachable_database_fails_fast() -> None:
    db = Database.from_dsn(_DEAD_DSN)
    try:
        with pytest.raises(StartupError) as excinfo:
            await validate_db_startup(db, make_settings(), connect_timeout=3.0)
    finally:
        await db.dispose()
    message = str(excinfo.value)
    assert "unreachable" in message
    assert "PLACEHOLDER_PW" not in message  # the DSN/password never leaks


def test_missing_alembic_config_wraps_as_startup_error() -> None:
    # A path with no alembic.ini → Alembic raises CommandError ("No
    # 'script_location' key found") rather than StartupError; main() does not map
    # CommandError to a clean exit, so an unwrapped one crash-loops the container
    # (the exact defect the shipped image hit before alembic.ini/ was baked in).
    # The wrap must turn it into a StartupError with an actionable, secret-free
    # message. Reads config only — no database needed, so this runs Docker-free.
    with pytest.raises(StartupError) as excinfo:
        _alembic_head("/no/such/dir/alembic.ini")
    message = str(excinfo.value)
    assert "alembic.ini" in message  # names the artifact the image must ship
    assert "/no/such/dir/alembic.ini" in message  # names the offending path
    assert "Traceback" not in message  # a wrapped fail-fast, not a leaked stack


# --------------------------------------------------------------------------- #
# Docker-gated checks against the migrated Postgres (via api_db).
# --------------------------------------------------------------------------- #
async def test_valid_migrated_db_passes(api_db: Database) -> None:
    await _insert(
        api_db,
        Backend(name="he", type="hurricane", config_encrypted=b"x"),
        TsigKey(name="cm-key.", algorithm="hmac-sha256", secret_encrypted=b"x"),
    )
    await validate_db_startup(api_db, make_settings())  # all preconditions hold


async def test_unknown_provider_row_fails_fast(api_db: Database) -> None:
    await _insert(
        api_db, Backend(name="weird", type="does-not-exist", config_encrypted=b"x")
    )
    with pytest.raises(StartupError, match="does-not-exist"):
        await validate_db_startup(api_db, make_settings())


async def test_bad_tsig_algorithm_row_fails_fast(api_db: Database) -> None:
    await _insert(
        api_db, TsigKey(name="k.", algorithm="hmac-bogus-512", secret_encrypted=b"x")
    )
    with pytest.raises(StartupError, match="hmac-bogus-512"):
        await validate_db_startup(api_db, make_settings())


async def test_stale_schema_fails_fast(
    api_db: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Simulate an empty/behind alembic_version without mutating the shared schema:
    # the reachability ping still passes, but current != head trips the check.
    async def _no_revision(engine: object) -> None:
        return None

    monkeypatch.setattr(startup_module, "_db_current_revision", _no_revision)
    with pytest.raises(StartupError, match="not current"):
        await validate_db_startup(api_db, make_settings())


async def test_bad_alembic_config_fails_fast_through_validate(
    api_db: Database,
) -> None:
    # End-to-end: the DB is reachable and at head, but an unresolvable alembic_ini
    # (step 3 of validate_db_startup) raises CommandError — it must surface as a
    # StartupError, never an uncaught crash. Proves the wrap holds on the real
    # validate_db_startup path, past the reachability ping.
    with pytest.raises(StartupError, match="alembic"):
        await validate_db_startup(
            api_db, make_settings(), alembic_ini="/no/such/dir/alembic.ini"
        )
