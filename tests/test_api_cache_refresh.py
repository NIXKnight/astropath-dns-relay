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

"""Cache-refresh hooks on management-API writes (T-M3-16, SPEC §6.4, MED-2).

Against real Postgres (Docker-gated) with a *live* DB-backed :class:`RoutingCache`
wired into the app exactly as ``main()`` does: creating or deleting a Domain / TSIG
key is visible to the data plane's in-memory cache immediately — no manual refresh,
no process restart (the AC). Throwaway key material only.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import dns.name
import httpx
import pytest_asyncio
from tests._api import api_client, seed_api_token
from tests.test_api_app import make_settings

from astropath.api.app import create_app
from astropath.cache import RoutingCache, make_db_loader
from astropath.crypto import Kek, generate_key
from astropath.db import Database

_KEK = Kek([generate_key()])
_HE_KEY = "throwaway-he-dynamic-key"


@pytest_asyncio.fixture
async def http_client() -> AsyncIterator[httpx.AsyncClient]:
    """A no-network client for provider construction inside the cache loader."""
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _req: httpx.Response(200, text="ok"))
    )
    try:
        yield client
    finally:
        await client.aclose()


@pytest_asyncio.fixture
async def wired(
    api_db: Database, http_client: httpx.AsyncClient
) -> AsyncIterator[tuple[httpx.AsyncClient, RoutingCache]]:
    """App + a real DB-backed cache, sharing one Database (the production wiring)."""
    cache = RoutingCache(make_db_loader(api_db.sessionmaker, _KEK, http_client))
    app = create_app(settings=make_settings(), database=api_db, cache=cache, kek=_KEK)
    headers = await seed_api_token(api_db)
    async with api_client(app) as client:
        client.headers.update(headers)
        yield client, cache


async def _seed_route(client: httpx.AsyncClient, zone: str = "example.com.") -> str:
    """Create a hurricane backend + a domain for ``zone``; return the zone."""
    backend = await client.post(
        "/api/v1/backends", json={"name": "he", "type": "hurricane", "config": {}}
    )
    backend_id = backend.json()["id"]
    created = await client.post(
        "/api/v1/domains",
        json={
            "zone": zone,
            "backend_id": backend_id,
            "record_name": f"_acme-challenge.{zone}",
            "he_dynamic_key": _HE_KEY,
        },
    )
    assert created.status_code == 201
    return zone


async def test_domain_create_is_visible_without_restart(
    wired: tuple[httpx.AsyncClient, RoutingCache],
) -> None:
    client, cache = wired
    zone = dns.name.from_text("example.com.")
    # Backend exists but no domain yet -> the zone does not route.
    await client.post(
        "/api/v1/backends", json={"name": "he", "type": "hurricane", "config": {}}
    )
    assert cache.match(zone) is None

    backend_id = (await client.get("/api/v1/backends")).json()[0]["id"]
    await client.post(
        "/api/v1/domains",
        json={
            "zone": "example.com.",
            "backend_id": backend_id,
            "record_name": "_acme-challenge.example.com.",
            "he_dynamic_key": _HE_KEY,
        },
    )
    # No manual cache.refresh() — the create hook already fired.
    assert cache.match(zone) is not None


async def test_domain_delete_is_visible_without_restart(
    wired: tuple[httpx.AsyncClient, RoutingCache],
) -> None:
    client, cache = wired
    await _seed_route(client)
    zone = dns.name.from_text("example.com.")
    assert cache.match(zone) is not None

    domain_id = (await client.get("/api/v1/domains")).json()[0]["id"]
    assert (await client.delete(f"/api/v1/domains/{domain_id}")).status_code == 204
    assert cache.match(zone) is None  # route withdrawn without restart


async def test_tsig_key_create_is_visible_without_restart(
    wired: tuple[httpx.AsyncClient, RoutingCache],
) -> None:
    client, cache = wired
    await _seed_route(client)  # a complete routing config for the loader
    key_name = dns.name.from_text("cm-key.")
    assert cache.tsig_key_id_for(key_name) is None

    created = await client.post("/api/v1/tsig-keys", json={"name": "cm-key."})
    assert created.status_code == 201
    # No manual refresh — the new key is already in the live keyring.
    assert cache.tsig_key_id_for(key_name) is not None
    assert key_name.canonicalize() in cache.keyring


async def test_tsig_key_delete_is_visible_without_restart(
    wired: tuple[httpx.AsyncClient, RoutingCache],
) -> None:
    client, cache = wired
    await _seed_route(client)
    created = await client.post("/api/v1/tsig-keys", json={"name": "cm-key."})
    key_id = created.json()["id"]
    key_name = dns.name.from_text("cm-key.")
    assert cache.tsig_key_id_for(key_name) is not None

    assert (await client.delete(f"/api/v1/tsig-keys/{key_id}")).status_code == 204
    assert cache.tsig_key_id_for(key_name) is None  # revoked without restart


async def test_write_succeeds_when_no_cache_is_wired(api_db: Database) -> None:
    """The hook is best-effort: a cache-less app still serves writes (get_optional)."""
    app = create_app(settings=make_settings(), database=api_db, kek=_KEK)
    headers = await seed_api_token(api_db)
    async with api_client(app) as client:
        client.headers.update(headers)
        created = await client.post("/api/v1/tsig-keys", json={"name": "nocache."})
        assert created.status_code == 201
