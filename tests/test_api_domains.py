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

"""Domains CRUD (T-M3-10, SPEC §9.1, HIGH-7).

Against real Postgres (Docker-gated): the HE per-record dynamic key is stored on
the Domain row, encrypted, and never returned on read (only ``has_secret``);
Route53-style domains store NULL. Unknown backend -> 422; duplicate zone -> 409.
Throwaway key material only.
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
from astropath.models import Domain
from astropath.store import SecretCodec

_KEK = Kek([generate_key()])
_HE_KEY = "throwaway-he-dynamic-key"


@pytest_asyncio.fixture
async def client(api_db: Database) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(settings=make_settings(), database=api_db, kek=_KEK)
    headers = await seed_api_token(api_db)
    async with api_client(app) as c:
        c.headers.update(headers)
        yield c


async def _make_backend(client: httpx.AsyncClient, name: str = "he") -> int:
    created = await client.post(
        "/api/v1/backends", json={"name": name, "type": "hurricane", "config": {}}
    )
    backend_id: int = created.json()["id"]
    return backend_id


async def test_create_stores_he_key_encrypted_and_hides_it(
    client: httpx.AsyncClient, api_db: Database
) -> None:
    backend_id = await _make_backend(client)
    response = await client.post(
        "/api/v1/domains",
        json={
            "zone": "example.com.",
            "backend_id": backend_id,
            "record_name": "_acme-challenge.example.com.",
            "he_dynamic_key": _HE_KEY,
        },
    )
    assert response.status_code == 201
    body = response.json()
    assert body["zone"] == "example.com."
    assert body["has_secret"] is True
    assert _HE_KEY not in response.text  # the key is never returned

    async with api_db.session() as session:
        domain = (await session.execute(select(Domain))).scalars().one()
    assert domain.secret_encrypted is not None
    assert _HE_KEY.encode() not in domain.secret_encrypted  # ciphertext at rest
    assert SecretCodec(_KEK).decrypt_text(domain.secret_encrypted) == _HE_KEY


async def test_route53_style_domain_stores_null_secret(
    client: httpx.AsyncClient, api_db: Database
) -> None:
    backend_id = await _make_backend(client, name="r53")
    response = await client.post(
        "/api/v1/domains",
        json={
            "zone": "aws.example.",
            "backend_id": backend_id,
            "record_name": "_acme-challenge.aws.example.",
        },
    )
    assert response.status_code == 201
    assert response.json()["has_secret"] is False
    async with api_db.session() as session:
        domain = (await session.execute(select(Domain))).scalars().one()
    assert domain.secret_encrypted is None


async def test_unknown_backend_is_422(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/api/v1/domains",
        json={
            "zone": "z.example.",
            "backend_id": 9999,
            "record_name": "_acme-challenge.z.example.",
        },
    )
    assert response.status_code == 422


async def test_duplicate_zone_is_409(client: httpx.AsyncClient) -> None:
    backend_id = await _make_backend(client)
    body = {
        "zone": "dup.example.",
        "backend_id": backend_id,
        "record_name": "_acme-challenge.dup.example.",
    }
    assert (await client.post("/api/v1/domains", json=body)).status_code == 201
    assert (await client.post("/api/v1/domains", json=body)).status_code == 409


async def test_list_never_returns_secret(client: httpx.AsyncClient) -> None:
    backend_id = await _make_backend(client)
    await client.post(
        "/api/v1/domains",
        json={
            "zone": "example.com.",
            "backend_id": backend_id,
            "record_name": "_acme-challenge.example.com.",
            "he_dynamic_key": _HE_KEY,
        },
    )
    listing = await client.get("/api/v1/domains")
    assert listing.status_code == 200
    assert _HE_KEY not in listing.text
    assert all(
        "secret" not in item or item.get("has_secret") in (True, False)
        for item in listing.json()
    )
    assert listing.json()[0]["has_secret"] is True


async def test_delete_and_delete_missing(client: httpx.AsyncClient) -> None:
    backend_id = await _make_backend(client)
    created = await client.post(
        "/api/v1/domains",
        json={
            "zone": "gone.example.",
            "backend_id": backend_id,
            "record_name": "_acme-challenge.gone.example.",
        },
    )
    domain_id = created.json()["id"]
    assert (await client.delete(f"/api/v1/domains/{domain_id}")).status_code == 204
    assert (await client.delete(f"/api/v1/domains/{domain_id}")).status_code == 404


async def test_requires_authentication(api_db: Database) -> None:
    app = create_app(settings=make_settings(), database=api_db, kek=_KEK)
    async with api_client(app) as c:
        assert (await c.get("/api/v1/domains")).status_code == 401
