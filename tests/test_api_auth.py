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

"""require_admin cookie-OR-header matrix (T-M3-02, SPEC §8.3, HIGH-5).

Exercised against the real ``create_app`` app via ``httpx.ASGITransport`` with a
fake :class:`AuthService` for the token path (no Postgres needed). Proves the 401
matrix: both-absent → 401 (FastAPI ≥ 0.122.0), cookie-only authorizes, header-only
authorizes, invalid credentials → 401. Throwaway token value only.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest_asyncio
from fastapi import Request
from tests.test_api_app import make_settings

from astropath.api.app import create_app
from astropath.api.session import mark_admin

_VALID_KEY = "throwaway-valid-api-token"
_SESSION_ROUTE = "/_test/login"


class _FakeAuth:
    """Accepts exactly one known API key; no database involved."""

    async def api_token_valid(self, api_key: str) -> bool:
        return api_key == _VALID_KEY


@pytest_asyncio.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(settings=make_settings())
    app.state.astropath.auth = _FakeAuth()

    async def _login(request: Request) -> dict[str, bool]:
        mark_admin(request)
        return {"ok": True}

    app.add_api_route(_SESSION_ROUTE, _login, methods=["POST"])

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="https://astropath.test"
    ) as c:
        yield c


async def test_both_absent_is_401(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/auth/session")
    assert response.status_code == 401


async def test_header_only_authorizes(client: httpx.AsyncClient) -> None:
    response = await client.get(
        "/api/v1/auth/session", headers={"X-API-Key": _VALID_KEY}
    )
    assert response.status_code == 200
    assert response.json() == {"authenticated": True}


async def test_header_invalid_is_401(client: httpx.AsyncClient) -> None:
    response = await client.get(
        "/api/v1/auth/session", headers={"X-API-Key": "wrong-token"}
    )
    assert response.status_code == 401


async def test_cookie_only_authorizes(client: httpx.AsyncClient) -> None:
    assert (await client.post(_SESSION_ROUTE)).status_code == 200
    response = await client.get("/api/v1/auth/session")  # cookie now on the jar
    assert response.status_code == 200
    assert response.json() == {"authenticated": True}


async def test_cookie_and_header_both_invalid_is_401(
    client: httpx.AsyncClient,
) -> None:
    # A bogus session cookie value plus a bogus header — neither authorizes.
    response = await client.get(
        "/api/v1/auth/session",
        headers={"Cookie": "session=tampered", "X-API-Key": "nope"},
    )
    assert response.status_code == 401
