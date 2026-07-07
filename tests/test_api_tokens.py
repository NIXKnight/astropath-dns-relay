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

"""API-token generation (T-M3-12, SPEC §9.1, §6.2, §8.1, LOW-1).

Against real Postgres (Docker-gated): the minted token is returned exactly once,
persisted only as a SHA-256 hash, never listed, and immediately usable for auth
(proving the constant-time hash compare works end-to-end). Throwaway tokens only.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest_asyncio
from sqlmodel import select
from tests._api import api_client, seed_api_token
from tests.test_api_app import make_settings

from astropath.api.app import create_app
from astropath.crypto import Kek, generate_key
from astropath.db import Database
from astropath.models import ApiToken
from astropath.store import hash_token

_KEK = Kek([generate_key()])


@pytest_asyncio.fixture
async def client(api_db: Database) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(settings=make_settings(), database=api_db, kek=_KEK)
    headers = await seed_api_token(api_db, name="seed")
    async with api_client(app) as c:
        c.headers.update(headers)
        yield c


async def test_create_returns_token_once_and_stores_hash_only(
    client: httpx.AsyncClient, api_db: Database
) -> None:
    response = await client.post("/api/v1/tokens", json={"name": "ci-runner"})
    assert response.status_code == 201
    body = response.json()
    assert body["name"] == "ci-runner"
    assert body["last_used_at"] is None
    token = body["token"]
    assert token  # high-entropy plaintext, revealed once

    async with api_db.session() as session:
        row = (
            (
                await session.execute(
                    select(ApiToken).where(ApiToken.name == "ci-runner")
                )
            )
            .scalars()
            .one()
        )
    # Only the SHA-256 hash is persisted — the plaintext is never stored.
    assert row.token_hash == hash_token(token)
    assert row.token_hash != token


async def test_list_never_returns_token_or_hash(
    client: httpx.AsyncClient, api_db: Database
) -> None:
    created = await client.post("/api/v1/tokens", json={"name": "listed"})
    token = created.json()["token"]

    async with api_db.session() as session:
        row = (
            (await session.execute(select(ApiToken).where(ApiToken.name == "listed")))
            .scalars()
            .one()
        )

    listing = await client.get("/api/v1/tokens")
    assert listing.status_code == 200
    assert token not in listing.text  # the plaintext never reappears
    assert row.token_hash not in listing.text  # nor the stored hash
    item = next(i for i in listing.json() if i["name"] == "listed")
    assert "token" not in item
    assert "token_hash" not in item
    assert set(item) == {"id", "name", "created_at", "last_used_at"}


async def test_created_token_authenticates(
    client: httpx.AsyncClient, api_db: Database
) -> None:
    created = await client.post("/api/v1/tokens", json={"name": "usable"})
    minted = created.json()["token"]

    # A brand-new client carrying only the minted token must authenticate — the
    # one-time value round-trips through the SHA-256 hash + constant-time compare.
    app = create_app(settings=make_settings(), database=api_db, kek=_KEK)
    async with api_client(app) as fresh:
        fresh.headers["X-API-Key"] = minted
        assert (await fresh.get("/api/v1/tokens")).status_code == 200
        # A tampered token is rejected.
        fresh.headers["X-API-Key"] = minted + "x"
        assert (await fresh.get("/api/v1/tokens")).status_code == 401


async def test_delete_and_delete_missing(client: httpx.AsyncClient) -> None:
    created = await client.post("/api/v1/tokens", json={"name": "revoke-me"})
    token_id = created.json()["id"]
    assert (await client.delete(f"/api/v1/tokens/{token_id}")).status_code == 204
    assert (await client.delete(f"/api/v1/tokens/{token_id}")).status_code == 404


async def test_revoked_token_stops_authenticating(
    client: httpx.AsyncClient, api_db: Database
) -> None:
    created = await client.post("/api/v1/tokens", json={"name": "short-lived"})
    minted = created.json()["token"]
    token_id = created.json()["id"]
    assert (await client.delete(f"/api/v1/tokens/{token_id}")).status_code == 204

    app = create_app(settings=make_settings(), database=api_db, kek=_KEK)
    async with api_client(app) as fresh:
        fresh.headers["X-API-Key"] = minted
        assert (await fresh.get("/api/v1/tokens")).status_code == 401


async def test_requires_authentication(api_db: Database) -> None:
    app = create_app(settings=make_settings(), database=api_db, kek=_KEK)
    async with api_client(app) as c:
        assert (await c.get("/api/v1/tokens")).status_code == 401
        assert (await c.post("/api/v1/tokens", json={"name": "x"})).status_code == 401
