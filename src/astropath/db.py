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

"""Async database engine, session factory, and dependency (SPEC §12.2, MED-1).

:class:`Database` owns one ``AsyncEngine`` + ``async_sessionmaker`` pair built
from a ``postgresql+asyncpg://`` DSN. It is constructed once by ``main()`` (the
single resource owner, MED-1) and disposed once on shutdown — never at import
time and never in a ``FastAPI(lifespan=...)`` hook.

``expire_on_commit=False`` is mandatory (SPEC §12.2): it prevents SQLAlchemy from
expiring ORM attributes after ``commit()``, which would otherwise trigger a lazy
reload — a blocking IO round-trip on attribute access — on the async path. The
sync ``with Session(engine)`` tutorial pattern is deliberately not used.

Seams for M3: :meth:`Database.get_session` is a FastAPI-ready dependency
(``Depends(db.get_session)``) and :meth:`Database.session` is an
``async with``-friendly context manager for imperative store/dispatcher code.
Schema creation is owned by Alembic (SPEC §12.1); this module never calls
``metadata.create_all``.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

__all__ = ["Database", "create_sessionmaker"]


def create_sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Build an ``async_sessionmaker`` bound to ``engine`` (SPEC §12.2).

    ``expire_on_commit=False`` avoids post-commit lazy-load IO on detached
    attributes; ``class_=AsyncSession`` yields async sessions.
    """
    return async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


class Database:
    """Owns the async engine + session factory for the process (MED-1).

    Construct with :meth:`from_dsn` in ``main()``; call :meth:`dispose` exactly
    once on shutdown. All persistence code obtains sessions through
    :meth:`session` or :meth:`get_session`.
    """

    __slots__ = ("_engine", "_sessionmaker")

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine
        self._sessionmaker = create_sessionmaker(engine)

    @classmethod
    def from_dsn(cls, dsn: str, *, echo: bool = False) -> Database:
        """Build from a ``postgresql+asyncpg://`` DSN (SPEC §10.2).

        The engine is created lazily — no connection is opened until the first
        session runs a statement — so construction never blocks or fails on a
        transiently-unreachable database.
        """
        return cls(create_async_engine(dsn, echo=echo, future=True))

    @property
    def engine(self) -> AsyncEngine:
        return self._engine

    @property
    def sessionmaker(self) -> async_sessionmaker[AsyncSession]:
        return self._sessionmaker

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        """Yield a session inside an ``async with`` block (imperative callers)."""
        async with self._sessionmaker() as session:
            yield session

    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """FastAPI dependency: yield one session per request (SPEC §12.2, M3).

        Used as ``Depends(db.get_session)``. The session is closed when the
        request scope exits.
        """
        async with self._sessionmaker() as session:
            yield session

    async def ping(self) -> None:
        """Run ``SELECT 1`` to prove reachability (startup fail-fast, T-M6-10)."""
        async with self._engine.connect() as connection:
            await connection.execute(text("SELECT 1"))

    async def dispose(self) -> None:
        """Dispose the engine's connection pool (once, on shutdown)."""
        await self._engine.dispose()
