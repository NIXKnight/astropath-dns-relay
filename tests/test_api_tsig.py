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

"""TSIG-key generation (T-M3-11, SPEC §9.1, HIGH-10, LOW-1).

Against real Postgres (Docker-gated): the minted secret is base64 BIND form,
returned exactly once at creation, encrypted at rest, and never listed. Invalid
algorithm -> 422; duplicate name -> 409. Throwaway key material only.
"""

from __future__ import annotations

import base64
from collections.abc import AsyncIterator

import httpx
import pytest_asyncio
from sqlmodel import select
from tests._api import api_client, seed_api_token
from tests.test_api_app import make_settings

from astropath.api.app import create_app
from astropath.crypto import Kek, generate_key
from astropath.db import Database
from astropath.models import TsigKey
from astropath.store import SecretCodec

_KEK = Kek([generate_key()])


@pytest_asyncio.fixture
async def client(api_db: Database) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(settings=make_settings(), database=api_db, kek=_KEK)
    headers = await seed_api_token(api_db)
    async with api_client(app) as c:
        c.headers.update(headers)
        yield c


async def test_create_returns_base64_bind_secret_once(
    client: httpx.AsyncClient, api_db: Database
) -> None:
    response = await client.post(
        "/api/v1/tsig-keys", json={"name": "cm-key.", "algorithm": "hmac-sha256"}
    )
    assert response.status_code == 201
    body = response.json()
    assert body["name"] == "cm-key."
    assert body["algorithm"] == "hmac-sha256"
    secret = body["secret"]
    # base64 BIND form of a 32-byte HMAC secret.
    assert len(base64.b64decode(secret)) == 32

    async with api_db.session() as session:
        row = (await session.execute(select(TsigKey))).scalars().one()
    assert secret.encode() not in row.secret_encrypted  # ciphertext at rest
    assert SecretCodec(_KEK).decrypt_text(row.secret_encrypted) == secret


async def test_list_never_returns_secret(client: httpx.AsyncClient) -> None:
    created = await client.post("/api/v1/tsig-keys", json={"name": "k1."})
    secret = created.json()["secret"]

    listing = await client.get("/api/v1/tsig-keys")
    assert listing.status_code == 200
    assert secret not in listing.text
    item = listing.json()[0]
    assert "secret" not in item
    assert item["name"] == "k1."
    assert item["algorithm"] == "hmac-sha256"


async def test_default_algorithm_is_hmac_sha256(client: httpx.AsyncClient) -> None:
    created = await client.post("/api/v1/tsig-keys", json={"name": "default."})
    assert created.json()["algorithm"] == "hmac-sha256"


async def test_invalid_algorithm_is_422(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/api/v1/tsig-keys", json={"name": "bad.", "algorithm": "hmac-nope"}
    )
    assert response.status_code == 422


async def test_duplicate_name_is_409(client: httpx.AsyncClient) -> None:
    assert (
        await client.post("/api/v1/tsig-keys", json={"name": "dup."})
    ).status_code == 201
    assert (
        await client.post("/api/v1/tsig-keys", json={"name": "dup."})
    ).status_code == 409


async def test_revoke_and_revoke_missing(client: httpx.AsyncClient) -> None:
    created = await client.post("/api/v1/tsig-keys", json={"name": "gone."})
    key_id = created.json()["id"]
    assert (await client.delete(f"/api/v1/tsig-keys/{key_id}")).status_code == 204
    assert (await client.delete(f"/api/v1/tsig-keys/{key_id}")).status_code == 404


async def test_requires_authentication(api_db: Database) -> None:
    app = create_app(settings=make_settings(), database=api_db, kek=_KEK)
    async with api_client(app) as c:
        assert (await c.get("/api/v1/tsig-keys")).status_code == 401
