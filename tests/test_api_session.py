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

"""Session-cookie tests (T-M3-03, SPEC §8.2).

Proves the signed-not-encrypted property ``[ASSERT]``: the ``session`` cookie
payload is client-readable base64 (no secret required to decode) yet tampering
invalidates it; the marker is opaque (``admin`` + ``iat`` only). Also pins the
SPEC §8.2 cookie flags on the real ``create_app`` middleware. Throwaway secret.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import AsyncIterator

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI, Request
from tests.test_api_app import make_settings

from astropath.api.app import create_app
from astropath.api.session import (
    SESSION_COOKIE,
    add_session_middleware,
    mark_admin,
    session_is_admin,
)


def _session_app() -> FastAPI:
    app = FastAPI()
    add_session_middleware(app, make_settings())

    @app.post("/login")
    async def login(request: Request) -> dict[str, bool]:
        mark_admin(request)
        return {"ok": True}

    @app.get("/whoami")
    async def whoami(request: Request) -> dict[str, bool]:
        return {"admin": session_is_admin(request)}

    return app


@pytest_asyncio.fixture
async def session_client() -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=_session_app())
    # https base_url so httpx honors the Secure cookie SessionMiddleware sets.
    async with httpx.AsyncClient(
        transport=transport, base_url="https://astropath.test"
    ) as c:
        yield c


def _decode_marker(cookie_value: str) -> dict[str, object]:
    """Decode the itsdangerous-signed session payload WITHOUT the secret.

    The signed cookie is ``<b64(json)>.<timestamp>.<signature>``; the first
    segment is the plain base64 of the JSON marker — readable because the cookie
    is signed, not encrypted.
    """
    data = cookie_value.split(".")[0]
    padded = data + "=" * (-len(data) % 4)
    decoded: dict[str, object] = json.loads(base64.b64decode(padded))
    return decoded


async def test_session_round_trips_admin_marker(
    session_client: httpx.AsyncClient,
) -> None:
    assert (await session_client.get("/whoami")).json() == {"admin": False}
    await session_client.post("/login")
    assert (await session_client.get("/whoami")).json() == {"admin": True}


async def test_cookie_is_signed_not_encrypted_and_opaque(
    session_client: httpx.AsyncClient,
) -> None:
    await session_client.post("/login")
    raw = session_client.cookies[SESSION_COOKIE]

    marker = _decode_marker(raw)  # decodes with NO secret -> not encrypted
    assert marker["admin"] is True
    # Opaque: only the marker keys, never a secret payload.
    assert set(marker) <= {"admin", "iat"}


async def test_tampering_invalidates_the_session(
    session_client: httpx.AsyncClient,
) -> None:
    await session_client.post("/login")
    raw = session_client.cookies[SESSION_COOKIE]

    # Flip a byte inside the signed payload segment -> signature no longer matches.
    head, sep, tail = raw.partition(".")
    flipped = ("A" if head[0] != "A" else "B") + head[1:]
    tampered = flipped + sep + tail
    response = await session_client.get(
        "/whoami", headers={"Cookie": f"{SESSION_COOKIE}={tampered}"}
    )
    assert response.json() == {"admin": False}  # dropped, not honored


def test_marker_payload_is_not_valid_base64_when_encrypted_would_be_opaque() -> None:
    # Guard the decode helper itself: a non-base64 blob raises, so the positive
    # test above genuinely proves readability rather than silently passing.
    with pytest.raises((binascii.Error, ValueError)):
        _decode_marker("!!!not-base64!!!.ts.sig")


def test_create_app_sets_spec_cookie_flags() -> None:
    app = create_app(settings=make_settings())
    session_mw = next(
        mw
        for mw in app.user_middleware
        if getattr(mw.cls, "__name__", "") == "SessionMiddleware"
    )
    kwargs = session_mw.kwargs
    assert kwargs["session_cookie"] == SESSION_COOKIE
    assert kwargs["same_site"] == "strict"
    assert kwargs["https_only"] is True
