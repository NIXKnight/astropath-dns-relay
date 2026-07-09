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

"""Per-plane readiness transitions (T-TEST-14, SPEC §2/§3, §11.2, HIGH-1).

Failure isolation and bounded restart are covered by :mod:`tests.test_supervisor`
(the ``supervise`` primitive); the server drain mechanics by
:mod:`tests.test_server`; the integrated two-plane clean/unhealthy shutdown by
:mod:`tests.test_main` (``serve()``). This suite proves the readiness composition
``main()`` wires: ``/readyz.dns`` tracks the DNS socket bind and flips back on
drain. Throwaway key material only.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator

import dns.name
import dns.tsig
import httpx
import pytest
from prometheus_client import CollectorRegistry
from tests.test_api_app import _FakeDB, make_settings
from tests.test_server import StubDispatcher

from astropath.api.app import create_app
from astropath.data_plane.server import Rfc2136Server
from astropath.observability import DataPlaneMetrics

Keyring = dict[dns.name.Name, dns.tsig.Key]


@pytest.fixture
async def readiness_client(
    keyring: Keyring,
) -> AsyncIterator[tuple[httpx.AsyncClient, Rfc2136Server]]:
    server = Rfc2136Server(
        keyring,
        StubDispatcher(),
        DataPlaneMetrics(registry=CollectorRegistry()),
        host="127.0.0.1",
        port=0,
    )

    def _dns_ready() -> bool:
        # The exact composition main() wires: sockets bound AND keyring loaded
        # AND routing cache populated (cache treated as populated here).
        return server.is_accepting and bool(keyring)

    app = create_app(
        settings=make_settings(),
        database=_FakeDB(reachable=True),  # type: ignore[arg-type]
        dns_ready=_dns_ready,
    )
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://astropath.test"
    ) as client:
        yield client, server


async def test_readyz_dns_field_tracks_socket_bind(
    readiness_client: tuple[httpx.AsyncClient, Rfc2136Server],
) -> None:
    client, server = readiness_client

    # Before bind: DNS not ready (overall not ready) even though the API plane is.
    body = (await client.get("/readyz")).json()
    assert body == {"ready": False, "dns": False, "api": True}

    ready = asyncio.Event()
    task = asyncio.create_task(server.serve(ready=ready))
    await asyncio.wait_for(ready.wait(), timeout=5.0)
    try:
        # Bound: both planes ready.
        body = (await client.get("/readyz")).json()
        assert body == {"ready": True, "dns": True, "api": True}

        # Draining: DNS flips back to not ready.
        server.stop_accepting()
        body = (await client.get("/readyz")).json()
        assert body["dns"] is False and body["ready"] is False
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
