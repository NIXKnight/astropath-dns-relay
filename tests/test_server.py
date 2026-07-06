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

"""RFC2136 listener transport tests (T-M1-11/12, SPEC §3.11).

Real round-trips against a server bound on an ephemeral loopback port. The
blocking dnspython client runs in a worker thread so the server's event loop
keeps running. Throwaway keys only.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator

import dns.name
import dns.query
import dns.rcode
import dns.tsig
import dns.update
import pytest
from prometheus_client import CollectorRegistry

from astropath.data_plane.server import Rfc2136Server
from astropath.observability import DataPlaneMetrics

Keyring = dict[dns.name.Name, dns.tsig.Key]


class StubDispatcher:
    """Always accepts (NOERROR); the transport is what's under test here."""

    async def dispatch(
        self, msg: dns.update.UpdateMessage, *, source: str
    ) -> dns.rcode.Rcode:
        return dns.rcode.NOERROR


def _signed_update(keyring: Keyring, keyname: str) -> dns.update.UpdateMessage:
    q = dns.update.UpdateMessage(
        "example.com.",
        keyname=dns.name.from_text(keyname),
        keyring=keyring,
        keyalgorithm=dns.tsig.HMAC_SHA256,
    )
    q.add("_acme-challenge.example.com.", 300, "TXT", "token-value")
    return q


@pytest.fixture
async def running_server(keyring: Keyring) -> AsyncIterator[Rfc2136Server]:
    server = Rfc2136Server(
        keyring,
        StubDispatcher(),
        DataPlaneMetrics(registry=CollectorRegistry()),
        host="127.0.0.1",
        port=0,
    )
    ready = asyncio.Event()
    task = asyncio.create_task(server.serve(ready=ready))
    await asyncio.wait_for(ready.wait(), timeout=5.0)
    try:
        yield server
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


async def test_udp_signed_update_round_trip(
    running_server: Rfc2136Server, keyring: Keyring, keyname: str
) -> None:
    query = _signed_update(keyring, keyname)
    response = await asyncio.to_thread(
        dns.query.udp, query, "127.0.0.1", 5.0, running_server.port
    )
    assert response.rcode() == dns.rcode.NOERROR
    assert response.had_tsig is True  # reply verified by the client


async def test_udp_unsigned_update_is_notauth(running_server: Rfc2136Server) -> None:
    unsigned = dns.update.UpdateMessage("example.com.")
    unsigned.add("_acme-challenge.example.com.", 300, "TXT", "tok")
    response = await asyncio.to_thread(
        dns.query.udp, unsigned, "127.0.0.1", 5.0, running_server.port
    )
    assert response.rcode() == dns.rcode.NOTAUTH
