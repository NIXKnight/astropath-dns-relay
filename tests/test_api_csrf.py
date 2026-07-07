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

"""CSRF origin protection (T-M3-06, SPEC §8.4, HIGH-5).

Cookie-authenticated mutating requests are origin-checked; a cross-origin (or
origin-less) POST is 403. An ``X-API-Key`` client is exempt (no ambient
credential). Safe methods and the unconfigured-origin case pass through.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest_asyncio
from fastapi import FastAPI
from tests._api import api_client
from tests.test_api_app import make_settings

from astropath.api.app import create_app

_ORIGIN = "https://astropath.test"
_EVIL = "https://evil.example"


class _FakeAuth:
    async def verify_admin_password(self, password: str) -> bool:
        return password == "pw"

    async def api_token_valid(self, api_key: str) -> bool:
        return False


def _app(origin: str | None) -> FastAPI:
    app = create_app(settings=make_settings(management_origin=origin))
    app.state.astropath.auth = _FakeAuth()
    return app


@pytest_asyncio.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    async with api_client(_app(_ORIGIN)) as c:
        yield c


async def test_matching_origin_passes(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/api/v1/auth/login", json={"password": "pw"}, headers={"Origin": _ORIGIN}
    )
    assert response.status_code == 200


async def test_cross_origin_cookie_post_is_403(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/api/v1/auth/login", json={"password": "pw"}, headers={"Origin": _EVIL}
    )
    assert response.status_code == 403


async def test_missing_origin_is_403(client: httpx.AsyncClient) -> None:
    response = await client.post("/api/v1/auth/login", json={"password": "pw"})
    assert response.status_code == 403


async def test_referer_fallback_is_honored(client: httpx.AsyncClient) -> None:
    ok = await client.post(
        "/api/v1/auth/login",
        json={"password": "pw"},
        headers={"Referer": f"{_ORIGIN}/backends/5"},
    )
    assert ok.status_code == 200


async def test_api_key_client_is_exempt(client: httpx.AsyncClient) -> None:
    # A non-browser token client bypasses the origin check (no ambient cookie);
    # it reaches the handler (401 here, never 403).
    response = await client.post(
        "/api/v1/auth/login",
        json={"password": "wrong"},
        headers={"Origin": _EVIL, "X-API-Key": "some-token"},
    )
    assert response.status_code != 403


async def test_safe_method_is_not_checked(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/auth/session", headers={"Origin": _EVIL})
    assert response.status_code == 401  # require_admin, not a CSRF 403


async def test_disabled_when_origin_unconfigured() -> None:
    async with api_client(_app(None)) as c:
        response = await c.post(
            "/api/v1/auth/login", json={"password": "pw"}, headers={"Origin": _EVIL}
        )
        assert response.status_code == 200  # check disabled -> reaches handler
