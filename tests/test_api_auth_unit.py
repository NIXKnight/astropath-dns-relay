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

"""API auth unit + session assertions (T-TEST-10, SPEC §8.2/§8.3, HIGH-5).

Consolidated auth pins: the require_admin 401 matrix (both-absent → 401 on
fastapi ≥ 0.122.0, cookie-only, header-only), and the session ``[ASSERT]`` set —
the cookie payload decodes without the secret (signed, not encrypted), tampering
invalidates it, and SessionMiddleware cannot run without a signing secret.
Throwaway credentials only.
"""

from __future__ import annotations

import base64
import json
from collections.abc import AsyncIterator
from typing import Any, cast

import httpx
import pytest
import pytest_asyncio
from starlette.middleware.sessions import SessionMiddleware
from tests.test_api_app import make_settings

from astropath.api.app import create_app
from astropath.api.session import SESSION_COOKIE

_PASSWORD = "throwaway-admin-pw"
_API_KEY = "throwaway-api-key-value"


class _FakeAuth:
    """Real-looking auth service: known password + known token, no database."""

    async def verify_admin_password(self, password: str) -> bool:
        return password == _PASSWORD

    async def api_token_valid(self, api_key: str) -> bool:
        return api_key == _API_KEY


@pytest_asyncio.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(settings=make_settings())
    app.state.astropath.auth = _FakeAuth()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="https://astropath.test"
    ) as c:
        yield c


# --------------------------------------------------------------------------- #
# require_admin 401 matrix
# --------------------------------------------------------------------------- #
async def test_both_absent_is_401(client: httpx.AsyncClient) -> None:
    assert (await client.get("/api/v1/auth/session")).status_code == 401


async def test_cookie_only_authorizes(client: httpx.AsyncClient) -> None:
    assert (
        await client.post("/api/v1/auth/login", json={"password": _PASSWORD})
    ).status_code == 200
    assert (await client.get("/api/v1/auth/session")).status_code == 200


async def test_header_only_authorizes(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/auth/session", headers={"X-API-Key": _API_KEY})
    assert response.status_code == 200


async def test_invalid_header_is_401(client: httpx.AsyncClient) -> None:
    response = await client.get(
        "/api/v1/auth/session", headers={"X-API-Key": "not-valid"}
    )
    assert response.status_code == 401


# --------------------------------------------------------------------------- #
# Session cookie [ASSERT] set
# --------------------------------------------------------------------------- #
def _decode_marker(cookie_value: str) -> dict[str, object]:
    data = cookie_value.split(".")[0]
    padded = data + "=" * (-len(data) % 4)
    decoded: dict[str, object] = json.loads(base64.b64decode(padded))
    return decoded


async def test_session_cookie_is_readable_without_the_secret(
    client: httpx.AsyncClient,
) -> None:
    await client.post("/api/v1/auth/login", json={"password": _PASSWORD})
    marker = _decode_marker(client.cookies[SESSION_COOKIE])
    assert marker["admin"] is True
    assert set(marker) <= {"admin", "iat"}  # opaque: no secret payload


async def test_tampered_cookie_is_rejected(client: httpx.AsyncClient) -> None:
    await client.post("/api/v1/auth/login", json={"password": _PASSWORD})
    raw = client.cookies[SESSION_COOKIE]
    head, sep, tail = raw.partition(".")
    tampered = ("A" if head[0] != "A" else "B") + head[1:] + sep + tail
    response = await client.get(
        "/api/v1/auth/session", headers={"Cookie": f"{SESSION_COOKIE}={tampered}"}
    )
    assert response.status_code == 401


def test_session_middleware_requires_a_secret_key() -> None:
    # Signed sessions are meaningless without a secret; the middleware cannot be
    # constructed without one (SPEC §8.2 [ASSERT]).
    with pytest.raises(TypeError):
        # secret_key is a required argument; its absence raises before app is used
        # (the omission is the point of the test, so the call-arg check is muted).
        SessionMiddleware(cast(Any, None))  # type: ignore[call-arg]
