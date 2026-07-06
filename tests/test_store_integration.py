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

"""Postgres testcontainers integration (T-TEST-12, SPEC §12.3, MED-3/MED-4).

Runs the store against a real ephemeral Postgres with the asyncpg driver (no
SQLite — dialect fidelity matters). ``alembic upgrade head`` is the first step
(catching model/metadata drift), then async CRUD, the DB-backed routing cache,
real ChallengeEvent audit writes, the bootstrap→DB migration, and KEK rotation
are all exercised end-to-end. The suite skips cleanly if Docker is unavailable.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Callable, Iterator

import dns.message
import dns.name
import dns.tsig
import dns.update
import httpx
import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from prometheus_client import CollectorRegistry
from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlmodel import select
from tests._fakes import FakeProvider, routing_for

from astropath.audit import DbAuditSink
from astropath.bootstrap import BootstrapConfig, ZoneConfig
from astropath.cache import RoutingCache, load_config_from_db, make_db_loader
from astropath.crypto import Kek, generate_key
from astropath.data_plane.dispatcher import Dispatcher
from astropath.data_plane.tsig import TsigKeySpec
from astropath.db import Database
from astropath.migrate_bootstrap import apply_migrations, insert_bootstrap_rows
from astropath.models import (
    AdminCredential,
    ApiToken,
    ChallengeEvent,
    Domain,
    TsigKey,
)
from astropath.observability import DataPlaneMetrics
from astropath.providers.hurricane import HurricaneProvider
from astropath.rotation import rotate_stored_secrets
from astropath.store import (
    SecretCodec,
    build_api_token,
    build_backend,
    build_domain,
    build_tsig_key,
    hash_password,
    verify_password,
    verify_token,
)

_TABLES = (
    "challengeevent",
    "domain",
    "tsigkey",
    "apitoken",
    "backend",
    "admincredential",
)
_HE_KEY = "he-dynamic-key-int"
_TSIG_SECRET_B64 = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="


@pytest.fixture(scope="session")
def postgres_dsn() -> Iterator[str]:
    """Start an ephemeral Postgres; yield its asyncpg DSN (skip if no Docker)."""
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
def migrated_dsn(postgres_dsn: str) -> str:
    """Apply ``alembic upgrade head`` once — the first step (SPEC §12.3)."""
    apply_migrations(postgres_dsn)
    return postgres_dsn


async def _truncate_all(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            text(f"TRUNCATE {', '.join(_TABLES)} RESTART IDENTITY CASCADE")
        )


@pytest_asyncio.fixture
async def db(migrated_dsn: str) -> AsyncIterator[Database]:
    """A clean Database per test (tables truncated), built in the test's loop."""
    database = Database.from_dsn(migrated_dsn)
    await _truncate_all(database.engine)
    try:
        yield database
    finally:
        await database.dispose()


@pytest_asyncio.fixture
async def http_client() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient() as client:
        yield client


def _codec(kek: Kek) -> SecretCodec:
    return SecretCodec(kek)


# --------------------------------------------------------------------------- #
# Migrations (the first step) + drift
# --------------------------------------------------------------------------- #
async def test_upgrade_head_builds_every_table(db: Database) -> None:
    async with db.engine.connect() as conn:
        tables = await conn.run_sync(lambda c: inspect(c).get_table_names())
    assert {
        "backend",
        "domain",
        "tsigkey",
        "apitoken",
        "challengeevent",
        "admincredential",
        "alembic_version",
    } <= set(tables)


def test_no_model_drift(migrated_dsn: str) -> None:
    # autogenerate against the live schema must produce no operations.
    os.environ["ASTROPATH_DATABASE_DSN"] = migrated_dsn
    command.check(Config("alembic.ini"))  # raises if the models drift from the DB


# --------------------------------------------------------------------------- #
# Async CRUD + encrypt-vs-hash at rest
# --------------------------------------------------------------------------- #
async def test_async_crud_round_trip_keeps_secrets_encrypted(db: Database) -> None:
    kek = Kek([generate_key()])
    codec = _codec(kek)

    async with db.session() as session:
        backend = build_backend(
            codec, name="he", backend_type="hurricane", config={"cleanup": "x"}
        )
        session.add(backend)
        await session.flush()
        assert backend.id is not None
        session.add(
            build_domain(
                codec,
                zone="example.com.",
                backend_id=backend.id,
                record_name="_acme-challenge.example.com.",
                he_dynamic_key=_HE_KEY,
            )
        )
        session.add(
            build_tsig_key(
                codec,
                name="cm-key.",
                algorithm="hmac-sha256",
                secret_b64=_TSIG_SECRET_B64,
            )
        )
        token_row, plaintext = build_api_token(name="ci")
        session.add(token_row)
        session.add(AdminCredential(id=1, password_hash=hash_password("pw")))
        await session.commit()

    async with db.session() as session:
        domain = (await session.execute(select(Domain))).scalars().one()
        tsig = (await session.execute(select(TsigKey))).scalars().one()
        token = (await session.execute(select(ApiToken))).scalars().one()
        admin = (await session.execute(select(AdminCredential))).scalars().one()

    # Reversible secrets are ciphertext at rest, but decrypt in memory.
    assert domain.secret_encrypted is not None
    assert _HE_KEY.encode() not in domain.secret_encrypted
    assert codec.decrypt_text(domain.secret_encrypted) == _HE_KEY
    assert codec.decrypt_text(tsig.secret_encrypted) == _TSIG_SECRET_B64
    # One-way material: token verifies via hash, password via argon2.
    assert verify_token(plaintext, token.token_hash) is True
    assert verify_password(admin.password_hash, "pw") is True


# --------------------------------------------------------------------------- #
# DB-backed routing cache serves from Postgres
# --------------------------------------------------------------------------- #
async def _seed_he_zone(db: Database, kek: Kek) -> None:
    async with db.session() as session:
        await insert_bootstrap_rows(
            session,
            BootstrapConfig(
                tsig_keys=[TsigKeySpec("cm-key.", "hmac-sha256", _TSIG_SECRET_B64)],
                zones=[
                    ZoneConfig(
                        "example.com.",
                        "hurricane",
                        "_acme-challenge.example.com.",
                        _HE_KEY,
                    )
                ],
            ),
            kek,
        )


async def test_cache_loads_and_serves_from_db(
    db: Database, http_client: httpx.AsyncClient
) -> None:
    kek = Kek([generate_key()])
    await _seed_he_zone(db, kek)

    cache = RoutingCache(make_db_loader(db.sessionmaker, kek, http_client))
    await cache.refresh()

    route = cache.match(dns.name.from_text("example.com."))
    assert route is not None
    assert isinstance(route.provider, HurricaneProvider)
    # The keyring (Key objects) and TSIG id map are rebuilt from the DB.
    assert dns.name.from_text("cm-key.") in cache.keyring
    assert cache.tsig_key_id_for(dns.name.from_text("cm-key.")) is not None


async def test_load_config_from_db_decrypts_he_key(db: Database) -> None:
    kek = Kek([generate_key()])
    await _seed_he_zone(db, kek)
    async with db.session() as session:
        config = await load_config_from_db(session, kek)
    assert [z.he_dynamic_key for z in config.zones] == [_HE_KEY]
    assert config.tsig_keys[0].secret_b64 == _TSIG_SECRET_B64


# --------------------------------------------------------------------------- #
# Real ChallengeEvent audit rows
# --------------------------------------------------------------------------- #
async def test_dispatch_writes_one_challenge_event_row(
    db: Database,
    keyring: dict[dns.name.Name, dns.tsig.Key],
    make_signed_update: Callable[..., bytes],
) -> None:
    kek = Kek([generate_key()])
    async with db.session() as session:
        session.add(
            build_tsig_key(
                _codec(kek),
                name="cm-key.",
                algorithm="hmac-sha256",
                secret_b64=_TSIG_SECRET_B64,
            )
        )
        await session.commit()
        tsig_id = (await session.execute(select(TsigKey.id))).scalars().one()

    provider = FakeProvider()
    dispatcher = Dispatcher(
        routing_for(provider),
        DataPlaneMetrics(registry=CollectorRegistry()),
        audit=DbAuditSink(db.sessionmaker),
        tsig_key_resolver=lambda _name: tsig_id,
    )

    msg = dns.message.from_wire(make_signed_update(value="tok"), keyring=keyring)
    assert isinstance(msg, dns.update.UpdateMessage)
    await dispatcher.dispatch(msg, source="1.2.3.4")

    async with db.session() as session:
        rows = (await session.execute(select(ChallengeEvent))).scalars().all()
    assert len(rows) == 1
    row = rows[0]
    assert row.zone == "example.com."
    assert row.action == "present"
    assert row.result == "ok"
    assert row.tsig_key_id == tsig_id
    assert row.source == "1.2.3.4"
    assert row.error_detail is None


# --------------------------------------------------------------------------- #
# Bootstrap → DB migration serves identically
# --------------------------------------------------------------------------- #
async def test_migrated_bootstrap_serves_identically(
    db: Database, http_client: httpx.AsyncClient
) -> None:
    kek = Kek([generate_key()])
    await _seed_he_zone(db, kek)  # same rows astropath-migrate-bootstrap would write

    cache = RoutingCache(make_db_loader(db.sessionmaker, kek, http_client))
    await cache.refresh()

    # The data plane resolves the zone and holds the HE per-record key —
    # identical service to the M1 file path, now sourced from Postgres.
    route = cache.match(dns.name.from_text("example.com."))
    assert route is not None
    assert route.record_name == dns.name.from_text("_acme-challenge.example.com.")
    provider = route.provider
    assert isinstance(provider, HurricaneProvider)
    assert provider._key_for("_acme-challenge.example.com.") == _HE_KEY


# --------------------------------------------------------------------------- #
# KEK rotation on a real DB
# --------------------------------------------------------------------------- #
async def test_rotate_stored_secrets_migrates_to_new_primary(db: Database) -> None:
    old_key = generate_key()
    old = Kek([old_key])
    await _seed_he_zone(db, old)

    new_key = generate_key()
    rotate_kek = Kek([new_key, old_key])
    async with db.session() as session:
        counts = await rotate_stored_secrets(session, rotate_kek)
    assert counts.total >= 2  # at least the TSIG secret + the HE domain key

    # After rotation everything decrypts under the NEW key alone.
    new_only = Kek([new_key])
    async with db.session() as session:
        config = await load_config_from_db(session, new_only)
    assert config.tsig_keys[0].secret_b64 == _TSIG_SECRET_B64
    assert config.zones[0].he_dynamic_key == _HE_KEY


# --------------------------------------------------------------------------- #
# Reachability smoke (startup fail-fast seam, T-M6-10)
# --------------------------------------------------------------------------- #
async def test_ping_succeeds(db: Database) -> None:
    await db.ping()
