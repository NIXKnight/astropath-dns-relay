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

"""Proxy-header trust behind nginx (T-M3-08, SPEC §8.6, HIGH-5).

Two proofs: (1) ``build_management_server`` wires ``proxy_headers=True`` and
``forwarded_allow_ips`` from settings onto the uvicorn Config (the real knob —
its default is localhost-only); (2) with the trust applied, an ``X-Forwarded-Proto:
https`` header rewrites the request scheme, so Secure-cookie / https detection
works behind nginx. Without proxy-header trust these headers are dropped.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest_asyncio
from fastapi import FastAPI, Request
from tests.test_api_app import make_settings
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from astropath.main import build_management_server
from astropath.settings import Settings


def test_settings_default_is_localhost_only() -> None:
    # SPEC §8.6: the default trust is localhost-only; production overrides it.
    assert Settings.model_fields["forwarded_allow_ips"].default == "127.0.0.1"


def test_management_server_wires_proxy_headers() -> None:
    settings = make_settings(forwarded_allow_ips="192.168.10.0/24")
    app = FastAPI()
    server = build_management_server(app, settings)
    assert server.config.proxy_headers is True
    assert server.config.forwarded_allow_ips == "192.168.10.0/24"
    assert server.config.lifespan == "off"


def _scheme_app() -> ProxyHeadersMiddleware:
    inner = FastAPI()

    @inner.get("/_scheme")
    async def scheme(request: Request) -> dict[str, str]:
        client = request.client.host if request.client else "?"
        return {"scheme": request.url.scheme, "client": client}

    # trusted_hosts="*" trusts every peer, isolating the header-rewrite behavior
    # from the ASGITransport client IP.
    return ProxyHeadersMiddleware(inner, trusted_hosts="*")  # type: ignore[arg-type]


@pytest_asyncio.fixture
async def proxied() -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=_scheme_app())  # type: ignore[arg-type]
    async with httpx.AsyncClient(
        transport=transport, base_url="http://astropath.test"
    ) as c:
        yield c


async def test_forwarded_proto_rewrites_scheme_to_https(
    proxied: httpx.AsyncClient,
) -> None:
    response = await proxied.get(
        "/_scheme",
        headers={"X-Forwarded-Proto": "https", "X-Forwarded-For": "203.0.113.7"},
    )
    body = response.json()
    assert body["scheme"] == "https"  # Secure-cookie detection works behind nginx
    assert body["client"] == "203.0.113.7"  # real client IP restored


async def test_without_forwarded_header_scheme_stays_http(
    proxied: httpx.AsyncClient,
) -> None:
    response = await proxied.get("/_scheme")
    assert response.json()["scheme"] == "http"
