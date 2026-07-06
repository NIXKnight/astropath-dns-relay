# SPDX-License-Identifier: GPL-3.0-or-later
#
# AstropathDNSRelay — self-hosted ACME DNS-01 solver gateway.
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

"""Async engine/session unit tests (T-M2-02, SPEC §12.2).

These need no live database: SQLAlchemy's async engine and sessions are lazy, so
constructing the :class:`Database`, taking a session, and disposing the engine
never open a connection. Real CRUD against Postgres runs in the testcontainers
suite (T-TEST-12).
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from astropath.db import Database, create_sessionmaker

_DSN = "postgresql+asyncpg://user:pass@localhost:5432/astropath"


def test_from_dsn_uses_asyncpg_driver() -> None:
    db = Database.from_dsn(_DSN)
    assert db.engine.url.drivername == "postgresql+asyncpg"


def test_sessionmaker_disables_expire_on_commit() -> None:
    db = Database.from_dsn(_DSN)
    # expire_on_commit=False is mandatory to avoid post-commit lazy-load IO.
    assert db.sessionmaker.kw["expire_on_commit"] is False


def test_create_sessionmaker_binds_engine() -> None:
    db = Database.from_dsn(_DSN)
    maker = create_sessionmaker(db.engine)
    assert maker.kw["expire_on_commit"] is False


async def test_get_session_yields_async_session() -> None:
    db = Database.from_dsn(_DSN)
    gen = db.get_session()
    session = await anext(gen)
    try:
        assert isinstance(session, AsyncSession)
    finally:
        await gen.aclose()
    await db.dispose()


async def test_session_context_manager_yields_async_session() -> None:
    db = Database.from_dsn(_DSN)
    async with db.session() as session:
        assert isinstance(session, AsyncSession)
    await db.dispose()
