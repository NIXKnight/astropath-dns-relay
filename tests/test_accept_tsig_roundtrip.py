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

"""Acceptance: TSIG round-trip through the bound server (T-TEST-02).

BLOCKER-1 + HIGH-2, end-to-end over a real loopback socket — the exact path
cert-manager's rfc2136 solver drives: a signed UPDATE is verified, dispatched to
the provider, and answered with a TSIG-signed reply the client verifies; an
unsigned UPDATE is refused NOTAUTH and never reaches the provider. The blocking
dnspython client runs in a worker thread so the server's loop keeps turning.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator

import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.tsig
import dns.update
import pytest
from prometheus_client import CollectorRegistry
from tests._fakes import FakeProvider, routing_for

from astropath.data_plane.dispatcher import Dispatcher
from astropath.data_plane.server import Rfc2136Server
from astropath.observability import DataPlaneMetrics

Keyring = dict[dns.name.Name, dns.tsig.Key]


class _Harness:
    def __init__(self, server: Rfc2136Server, provider: FakeProvider) -> None:
        self.server = server
        self.provider = provider

    @property
    def port(self) -> int:
        return self.server.port


@pytest.fixture
async def harness(keyring: Keyring) -> AsyncIterator[_Harness]:
    provider = FakeProvider()
    dispatcher = Dispatcher(
        routing_for(provider), DataPlaneMetrics(registry=CollectorRegistry())
    )
    server = Rfc2136Server(
        keyring,
        dispatcher,
        DataPlaneMetrics(registry=CollectorRegistry()),
        host="127.0.0.1",
        port=0,
    )
    ready = asyncio.Event()
    task = asyncio.create_task(server.serve(ready=ready))
    await asyncio.wait_for(ready.wait(), timeout=5.0)
    try:
        yield _Harness(server, provider)
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


def _signed_add(
    keyring: Keyring, *, value: str = "token-value"
) -> dns.update.UpdateMessage:
    update = dns.update.UpdateMessage(
        "example.com.",
        keyname=dns.name.from_text("cm-key."),
        keyring=keyring,
        keyalgorithm=dns.tsig.HMAC_SHA256,
    )
    update.add("_acme-challenge.example.com.", 300, "TXT", value)
    return update


async def test_signed_update_over_udp_is_verified_dispatched_and_signed(
    harness: _Harness, keyring: Keyring
) -> None:
    response = await asyncio.to_thread(
        dns.query.udp, _signed_add(keyring), "127.0.0.1", 5.0, harness.port
    )

    assert response.rcode() == dns.rcode.NOERROR  # accepted
    assert response.had_tsig is True  # reply TSIG verified by the client
    # The verified challenge reached the provider with the raw token.
    assert harness.provider.present_calls == [
        ("example.com.", "_acme-challenge.example.com.", ("token-value",))
    ]


async def test_signed_update_over_tcp_round_trips(
    harness: _Harness, keyring: Keyring
) -> None:
    response = await asyncio.to_thread(
        dns.query.tcp, _signed_add(keyring), "127.0.0.1", 5.0, harness.port
    )

    assert response.rcode() == dns.rcode.NOERROR
    assert response.had_tsig is True
    assert len(harness.provider.present_calls) == 1


async def test_unsigned_update_is_notauth_and_never_dispatched(
    harness: _Harness,
) -> None:
    unsigned = dns.update.UpdateMessage("example.com.")
    unsigned.add("_acme-challenge.example.com.", 300, "TXT", "token-value")

    response = await asyncio.to_thread(
        dns.query.udp, unsigned, "127.0.0.1", 5.0, harness.port
    )

    assert response.rcode() == dns.rcode.NOTAUTH  # auth gate rejected it
    assert harness.provider.present_calls == []  # provider never touched
