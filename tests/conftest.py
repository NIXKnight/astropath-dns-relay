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

"""Shared pytest fixtures for the astropath-dns-relay test suite.

The TSIG/DNS builder fixtures below are reused by the protocol, dispatcher, and
server tests. All key material is obvious throwaway bytes; no real secret exists
in this repository (SPEC secret discipline).
"""

from __future__ import annotations

import base64
from collections.abc import AsyncIterator, Callable, Iterator

import dns.name
import dns.tsig
import dns.update
import pytest
import pytest_asyncio

from astropath.data_plane.tsig import TsigKeySpec, build_keyring
from astropath.db import Database
from astropath.observability import DataPlaneMetrics

# Reusable throwaway TSIG identity.
KEYNAME = "cm-key."
SECRET_B64 = base64.b64encode(b"0123456789abcdef0123456789abcdef").decode()

# A signed-UPDATE builder: (zone, record, value, delete?, sign_keyring?) -> wire.
UpdateBuilder = Callable[..., bytes]


@pytest.fixture
def keyname() -> str:
    return KEYNAME


@pytest.fixture
def keyring() -> dict[dns.name.Name, dns.tsig.Key]:
    return build_keyring([TsigKeySpec(KEYNAME, "hmac-sha256", SECRET_B64)])


@pytest.fixture
def metrics() -> DataPlaneMetrics:
    from prometheus_client import CollectorRegistry

    return DataPlaneMetrics(registry=CollectorRegistry())


@pytest.fixture
def make_signed_update(
    keyring: dict[dns.name.Name, dns.tsig.Key],
) -> UpdateBuilder:
    def _make(
        zone: str = "example.com.",
        record: str = "_acme-challenge.example.com.",
        value: str = "token-value-abc",
        *,
        delete: bool = False,
        delete_rrset: bool = False,
        sign_keyring: dict[dns.name.Name, dns.tsig.Key] | None = None,
    ) -> bytes:
        u = dns.update.UpdateMessage(
            zone,
            keyname=dns.name.from_text(KEYNAME),
            keyring=sign_keyring if sign_keyring is not None else keyring,
            keyalgorithm=dns.tsig.HMAC_SHA256,
        )
        if delete_rrset:
            u.delete(record, "TXT")
        elif delete:
            u.delete(record, "TXT", value)
        else:
            u.add(record, 300, "TXT", value)
        return u.to_wire()

    return _make


@pytest.fixture
def make_unsigned_update() -> UpdateBuilder:
    def _make(
        zone: str = "example.com.",
        record: str = "_acme-challenge.example.com.",
        value: str = "token-value-abc",
        *,
        delete: bool = False,
    ) -> bytes:
        u = dns.update.UpdateMessage(zone)
        if delete:
            u.delete(record, "TXT", value)
        else:
            u.add(record, 300, "TXT", value)
        return u.to_wire()

    return _make


# --------------------------------------------------------------------------- #
# Shared ephemeral Postgres for the management-API integration suites (T-M3-*).
# Docker-gated: skips cleanly when Docker/testcontainers is unavailable, matching
# the store integration suite. No SQLite — SPEC §12.3 requires dialect fidelity.
# --------------------------------------------------------------------------- #
_API_TABLES = (
    "challengeevent",
    "domain",
    "tsigkey",
    "apitoken",
    "backend",
    "admincredential",
)


@pytest.fixture(scope="session")
def pg_dsn() -> Iterator[str]:
    """Start an ephemeral Postgres; yield its asyncpg DSN (skip without Docker)."""
    try:
        from testcontainers.postgres import (  # type: ignore[import-untyped]
            PostgresContainer,
        )
    except ImportError:  # pragma: no cover
        pytest.skip("testcontainers not installed")

    try:
        container = PostgresContainer("postgres:16-alpine", driver="asyncpg")
        container.start()
    except Exception as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"Docker/Postgres unavailable: {exc}")

    try:
        yield container.get_connection_url(driver="asyncpg")
    finally:
        container.stop()


@pytest.fixture(scope="session")
def pg_migrated(pg_dsn: str) -> str:
    """Apply ``alembic upgrade head`` once against the shared container."""
    from astropath.migrate_bootstrap import apply_migrations

    apply_migrations(pg_dsn)
    return pg_dsn


@pytest_asyncio.fixture
async def api_db(pg_migrated: str) -> AsyncIterator[Database]:
    """A clean :class:`Database` per test (all API tables truncated)."""
    from sqlalchemy import text

    database = Database.from_dsn(pg_migrated)
    async with database.engine.begin() as conn:
        await conn.execute(
            text(f"TRUNCATE {', '.join(_API_TABLES)} RESTART IDENTITY CASCADE")
        )
    try:
        yield database
    finally:
        await database.dispose()
