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

"""Login / logout flow (T-M3-04, SPEC §8, §9.1, HIGH-5).

The env-seeded argon2id hash is the credential (no DB needed for this path). A
correct password sets the session cookie and authorizes the protected probe; a
wrong password returns 401 and never echoes the password. Throwaway credential.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest_asyncio
from pydantic import SecretStr
from tests.test_api_app import make_settings

from astropath.api.app import create_app
from astropath.store import hash_password

_PASSWORD = "throwaway-correct-horse-battery"


@pytest_asyncio.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    settings = make_settings(admin_password_hash=SecretStr(hash_password(_PASSWORD)))
    transport = httpx.ASGITransport(app=create_app(settings=settings))
    async with httpx.AsyncClient(
        transport=transport, base_url="https://astropath.test"
    ) as c:
        yield c


async def test_login_success_sets_session_and_authorizes(
    client: httpx.AsyncClient,
) -> None:
    response = await client.post("/api/v1/auth/login", json={"password": _PASSWORD})
    assert response.status_code == 200
    assert response.json() == {"authenticated": True}
    # The session cookie now authorizes the protected probe.
    assert (await client.get("/api/v1/auth/session")).status_code == 200


async def test_wrong_password_is_401_and_does_not_leak(
    client: httpx.AsyncClient,
) -> None:
    response = await client.post(
        "/api/v1/auth/login", json={"password": "not-the-password"}
    )
    assert response.status_code == 401
    assert "not-the-password" not in response.text
    # No session was established.
    assert (await client.get("/api/v1/auth/session")).status_code == 401


async def test_logout_clears_the_session(client: httpx.AsyncClient) -> None:
    await client.post("/api/v1/auth/login", json={"password": _PASSWORD})
    assert (await client.get("/api/v1/auth/session")).status_code == 200

    assert (await client.post("/api/v1/auth/logout")).status_code == 200
    assert (await client.get("/api/v1/auth/session")).status_code == 401


async def test_empty_password_is_rejected_by_validation(
    client: httpx.AsyncClient,
) -> None:
    # min_length=1 -> 422 before any argon2 work.
    response = await client.post("/api/v1/auth/login", json={"password": ""})
    assert response.status_code == 422
