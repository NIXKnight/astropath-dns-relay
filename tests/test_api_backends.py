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

"""Backends CRUD (T-M3-09, SPEC §9.1, HIGH-9).

Against real Postgres (Docker-gated): create validates provider type + config and
re-encrypts it; reads never return the config; unknown type / bad config -> 422;
DELETE is 409 while a Domain references it. Throwaway values only.
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
from astropath.models import Backend
from astropath.store import SecretCodec, build_domain

_KEK = Kek([generate_key()])


@pytest_asyncio.fixture
async def client(api_db: Database) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(settings=make_settings(), database=api_db, kek=_KEK)
    headers = await seed_api_token(api_db)
    async with api_client(app) as c:
        c.headers.update(headers)
        yield c


async def test_create_returns_metadata_without_config(
    client: httpx.AsyncClient,
) -> None:
    response = await client.post(
        "/api/v1/backends",
        json={
            "name": "he-primary",
            "type": "hurricane",
            "config": {"cleanup_placeholder": "cleared"},
        },
    )
    assert response.status_code == 201
    body = response.json()
    assert body["name"] == "he-primary"
    assert body["type"] == "hurricane"
    assert "config" not in body  # write-only: config never returned


async def test_created_config_is_encrypted_at_rest(
    client: httpx.AsyncClient, api_db: Database
) -> None:
    await client.post(
        "/api/v1/backends",
        json={
            "name": "he",
            "type": "hurricane",
            "config": {"cleanup_placeholder": "sentinel-xyz"},
        },
    )
    async with api_db.session() as session:
        backend = (await session.execute(select(Backend))).scalars().one()
    assert b"sentinel-xyz" not in backend.config_encrypted  # ciphertext at rest
    assert SecretCodec(_KEK).decrypt_json(backend.config_encrypted) == {
        "cleanup_placeholder": "sentinel-xyz"
    }


async def test_unknown_type_is_422(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/api/v1/backends", json={"name": "x", "type": "nope", "config": {}}
    )
    assert response.status_code == 422


async def test_invalid_config_is_422_without_echoing_value(
    client: httpx.AsyncClient,
) -> None:
    response = await client.post(
        "/api/v1/backends",
        json={
            "name": "x",
            "type": "hurricane",
            "config": {"cleanup_placeholder": ["not", "a", "string"]},
        },
    )
    assert response.status_code == 422
    assert "not" not in response.text  # rejected input value not echoed back


async def test_duplicate_name_is_409(client: httpx.AsyncClient) -> None:
    body = {"name": "dup", "type": "hurricane", "config": {}}
    assert (await client.post("/api/v1/backends", json=body)).status_code == 201
    assert (await client.post("/api/v1/backends", json=body)).status_code == 409


async def test_list_and_get_omit_config(client: httpx.AsyncClient) -> None:
    created = await client.post(
        "/api/v1/backends", json={"name": "he", "type": "hurricane", "config": {}}
    )
    backend_id = created.json()["id"]

    listing = await client.get("/api/v1/backends")
    assert listing.status_code == 200
    assert all("config" not in item for item in listing.json())

    got = await client.get(f"/api/v1/backends/{backend_id}")
    assert got.status_code == 200
    assert "config" not in got.json()
    assert (await client.get("/api/v1/backends/9999")).status_code == 404


async def test_patch_name_and_config(
    client: httpx.AsyncClient, api_db: Database
) -> None:
    created = await client.post(
        "/api/v1/backends",
        json={
            "name": "old",
            "type": "hurricane",
            "config": {"cleanup_placeholder": "a"},
        },
    )
    backend_id = created.json()["id"]

    patched = await client.patch(
        f"/api/v1/backends/{backend_id}",
        json={"name": "new", "config": {"cleanup_placeholder": "b"}},
    )
    assert patched.status_code == 200
    assert patched.json()["name"] == "new"

    async with api_db.session() as session:
        backend = await session.get(Backend, backend_id)
    assert backend is not None
    assert SecretCodec(_KEK).decrypt_json(backend.config_encrypted) == {
        "cleanup_placeholder": "b"
    }


async def test_delete_and_delete_missing(client: httpx.AsyncClient) -> None:
    created = await client.post(
        "/api/v1/backends", json={"name": "gone", "type": "hurricane", "config": {}}
    )
    backend_id = created.json()["id"]
    assert (await client.delete(f"/api/v1/backends/{backend_id}")).status_code == 204
    assert (await client.get(f"/api/v1/backends/{backend_id}")).status_code == 404
    assert (await client.delete(f"/api/v1/backends/{backend_id}")).status_code == 404


async def test_delete_is_409_when_referenced_by_a_domain(
    client: httpx.AsyncClient, api_db: Database
) -> None:
    created = await client.post(
        "/api/v1/backends", json={"name": "ref", "type": "hurricane", "config": {}}
    )
    backend_id = created.json()["id"]
    async with api_db.session() as session:
        session.add(
            build_domain(
                SecretCodec(_KEK),
                zone="example.com.",
                backend_id=backend_id,
                record_name="_acme-challenge.example.com.",
            )
        )
        await session.commit()

    assert (await client.delete(f"/api/v1/backends/{backend_id}")).status_code == 409


async def test_requires_authentication(api_db: Database) -> None:
    app = create_app(settings=make_settings(), database=api_db, kek=_KEK)
    async with api_client(app) as c:  # no token seeded / sent
        assert (await c.get("/api/v1/backends")).status_code == 401
