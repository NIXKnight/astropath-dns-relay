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

"""FastAPI / uvicorn build-time asserts (T-TEST-15, SPEC §2.2, MED-1, HIGH-5).

Pins the version-sensitive embedding facts against the *installed* uvicorn/FastAPI
so the management-plane wiring cannot silently rot:

- ``Config(lifespan="off")`` is accepted (main() owns startup/teardown, no
  double-init: create_app serves from the injected resources verbatim).
- ``proxy_headers`` defaults True; ``forwarded_allow_ips`` Config default is None
  (uvicorn then trusts localhost only) — our Settings default is 127.0.0.1.
- Signal ownership: uvicorn 0.50 renamed ``install_signal_handlers`` to the
  ``capture_signals()`` context manager (SPEC §2.2 [ASSERT] anticipated this
  drift); ``build_management_server`` neutralizes it so main() owns SIGTERM/SIGINT,
  and graceful stop is driven by ``server.should_exit``.
- Missing credential -> 401 on FastAPI >= 0.122.0 (pinned).
"""

from __future__ import annotations

import signal
from collections.abc import AsyncIterator

import fastapi
import httpx
import pytest_asyncio
import uvicorn
from fastapi import FastAPI
from tests.test_api_app import make_settings

from astropath.api.app import create_app
from astropath.main import build_management_server
from astropath.settings import Settings


def test_config_accepts_lifespan_off() -> None:
    config = uvicorn.Config(FastAPI(), lifespan="off")
    assert config.lifespan == "off"


def test_proxy_headers_default_is_true() -> None:
    assert uvicorn.Config(FastAPI()).proxy_headers is True


def test_forwarded_allow_ips_config_default_is_localhost_only() -> None:
    # SPEC §8.6 [ASSERT]: uvicorn resolves the effective forwarded_allow_ips to
    # localhost-only when unset, so behind nginx it MUST be set explicitly. Our
    # Settings surface makes that override a first-class field.
    assert uvicorn.Config(FastAPI()).forwarded_allow_ips == "127.0.0.1"
    assert Settings.model_fields["forwarded_allow_ips"].default == "127.0.0.1"


def test_server_exposes_should_exit() -> None:
    server = uvicorn.Server(uvicorn.Config(FastAPI(), lifespan="off"))
    assert hasattr(server, "should_exit")
    assert server.should_exit is False


def test_signal_capture_api_shape() -> None:
    # SPEC §2.2 [ASSERT]: the old install_signal_handlers method is gone in the
    # pinned uvicorn; capture_signals() is the current mechanism serve() enters.
    server = uvicorn.Server(uvicorn.Config(FastAPI(), lifespan="off"))
    assert not hasattr(server, "install_signal_handlers")
    assert hasattr(server, "capture_signals")


def test_build_management_server_does_not_grab_signals() -> None:
    server = build_management_server(FastAPI(), make_settings())
    before = signal.getsignal(signal.SIGTERM)
    with server.capture_signals():
        # Neutralized: uvicorn does not replace main()'s SIGTERM handler.
        assert signal.getsignal(signal.SIGTERM) is before
    assert signal.getsignal(signal.SIGTERM) is before


def test_fastapi_version_pins_401_semantics() -> None:
    major, minor, *_ = (int(p) for p in fastapi.__version__.split(".")[:2])
    assert (major, minor) >= (0, 122)


@pytest_asyncio.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=create_app(settings=make_settings()))
    async with httpx.AsyncClient(
        transport=transport, base_url="https://astropath.test"
    ) as c:
        yield c


async def test_missing_credential_is_401(client: httpx.AsyncClient) -> None:
    assert (await client.get("/api/v1/auth/session")).status_code == 401
