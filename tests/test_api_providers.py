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

"""Provider config-schema endpoint (T-M4-03, SPEC §5.2, HIGH-9).

``GET /api/v1/backends/providers`` surfaces each registered provider's
``config_schema()`` as JSON Schema so the SPA credential form is generated
automatically. It is auth-gated, exposes only config *shape* (secret fields are
``writeOnly``), and must not be shadowed by the ``/{backend_id}`` int route.
Docker-gated via ``api_db`` (seeds an ``X-API-Key`` for CSRF-exempt auth).
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest_asyncio
from tests._api import api_client, seed_api_token
from tests.test_api_app import make_settings

from astropath.api.app import create_app
from astropath.db import Database


@pytest_asyncio.fixture
async def client(api_db: Database) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(settings=make_settings(), database=api_db)
    headers = await seed_api_token(api_db)
    async with api_client(app) as c:
        c.headers.update(headers)
        yield c


async def test_lists_registered_providers_with_schemas(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get("/api/v1/backends/providers")
    assert response.status_code == 200
    by_type = {provider["type"]: provider for provider in response.json()}
    assert {"hurricane", "route53"} <= set(by_type)

    he = by_type["hurricane"]
    assert he["supports_delete"] is False
    assert he["supports_multivalue"] is False
    assert "cleanup_placeholder" in he["config_schema"]["properties"]


async def test_route53_secret_field_is_write_only(client: httpx.AsyncClient) -> None:
    body = (await client.get("/api/v1/backends/providers")).json()
    route53 = next(provider for provider in body if provider["type"] == "route53")
    secret = route53["config_schema"]["properties"]["secret_access_key"]
    # A pydantic SecretStr renders as a write-only password field so the UI masks
    # it and never treats it as a value to redisplay.
    assert secret.get("writeOnly") is True
    assert secret.get("format") == "password"
    assert route53["supports_multivalue"] is True


async def test_providers_endpoint_requires_auth(api_db: Database) -> None:
    app = create_app(settings=make_settings(), database=api_db)
    async with api_client(app) as unauth:  # no token seeded / sent
        assert (await unauth.get("/api/v1/backends/providers")).status_code == 401


async def test_providers_not_parsed_as_backend_id(client: httpx.AsyncClient) -> None:
    # Registered before GET /{backend_id}: "providers" resolves to the list route
    # rather than failing int coercion of the path parameter.
    response = await client.get("/api/v1/backends/providers")
    assert response.status_code == 200
    assert isinstance(response.json(), list)
