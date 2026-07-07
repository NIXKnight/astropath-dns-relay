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

"""RFC2136 listener transport tests (T-M1-11/12, SPEC §3.11).

Real round-trips against a server bound on an ephemeral loopback port. The
blocking dnspython client runs in a worker thread so the server's event loop
keeps running. Throwaway keys only.
"""

from __future__ import annotations

import asyncio
import contextlib
import struct
from collections.abc import AsyncIterator

import dns.exception
import dns.name
import dns.query
import dns.rcode
import dns.tsig
import dns.update
import pytest
from prometheus_client import CollectorRegistry

from astropath.data_plane.server import Rfc2136Server, _UdpProtocol
from astropath.observability import DataPlaneMetrics

Keyring = dict[dns.name.Name, dns.tsig.Key]


class StubDispatcher:
    """Always accepts (NOERROR); the transport is what's under test here."""

    async def dispatch(
        self, msg: dns.update.UpdateMessage, *, source: str
    ) -> dns.rcode.Rcode:
        return dns.rcode.NOERROR


class BlockingDispatcher:
    """Blocks inside dispatch until released — drives the drain tests (T-M6-05)."""

    def __init__(self) -> None:
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.completed = 0

    async def dispatch(
        self, msg: dns.update.UpdateMessage, *, source: str
    ) -> dns.rcode.Rcode:
        self.entered.set()
        await self.release.wait()
        self.completed += 1
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


def _big_signed_update(keyring: Keyring, keyname: str) -> dns.update.UpdateMessage:
    q = _signed_update(keyring, keyname)
    i = 0
    while len(q.to_wire()) <= 600:  # push comfortably over the 512-byte UDP limit
        q.present(f"pad{i}.example.com.", "A")  # prerequisite padding (ignored)
        i += 1
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


def test_connection_made_stores_transport_without_isinstance_assert() -> None:
    """``connection_made`` narrows by type only — never a runtime isinstance check.

    On CPython < 3.12 the concrete ``_SelectorDatagramTransport`` is not an
    ``asyncio.DatagramTransport`` subclass (that base arrived in 3.12), so a
    runtime ``isinstance`` assert here would raise inside the loop callback, get
    swallowed by the event loop, and leave ``_transport`` None — the UDP listener
    would then silently never reply. Handing a plain ``BaseTransport`` stand-in
    (which no interpreter treats as a ``DatagramTransport``) reproduces that shape
    and guards the store-the-transport contract on every interpreter.
    """
    proto = _UdpProtocol(
        lambda: {},
        StubDispatcher(),
        DataPlaneMetrics(registry=CollectorRegistry()),
    )
    transport = asyncio.BaseTransport()
    proto.connection_made(transport)
    assert proto._transport is transport


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


async def test_tcp_large_signed_update_round_trip(
    running_server: Rfc2136Server, keyring: Keyring, keyname: str
) -> None:
    query = _big_signed_update(keyring, keyname)
    assert len(query.to_wire()) > 512  # exceeds the UDP payload limit -> needs TCP
    response = await asyncio.to_thread(
        dns.query.tcp, query, "127.0.0.1", 5.0, running_server.port
    )
    assert response.rcode() == dns.rcode.NOERROR
    assert response.had_tsig is True


async def test_malformed_tcp_message_closes_without_crash(
    running_server: Rfc2136Server, keyring: Keyring, keyname: str
) -> None:
    import struct

    reader, writer = await asyncio.open_connection("127.0.0.1", running_server.port)
    writer.write(struct.pack("!H", 20) + b"\xff" * 20)  # framed garbage
    await writer.drain()
    with contextlib.suppress(Exception):
        await asyncio.wait_for(reader.read(1), timeout=1.0)  # server closes -> EOF
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()

    # The listener survives: a subsequent valid query still succeeds.
    response = await asyncio.to_thread(
        dns.query.udp,
        _signed_update(keyring, keyname),
        "127.0.0.1",
        5.0,
        running_server.port,
    )
    assert response.rcode() == dns.rcode.NOERROR


# --------------------------------------------------------------------------- #
# T-M6-05: graceful drain (stop accepting -> drain in-flight -> close sockets).
# --------------------------------------------------------------------------- #
async def _serve_with(
    dispatcher: object, keyring: Keyring
) -> tuple[Rfc2136Server, asyncio.Task[None]]:
    server = Rfc2136Server(
        keyring,
        dispatcher,  # type: ignore[arg-type]
        DataPlaneMetrics(registry=CollectorRegistry()),
        host="127.0.0.1",
        port=0,
    )
    ready = asyncio.Event()
    task = asyncio.create_task(server.serve(ready=ready))
    await asyncio.wait_for(ready.wait(), timeout=5.0)
    return server, task


async def _cancel(task: asyncio.Task[None]) -> None:
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


async def test_is_accepting_transitions(keyring: Keyring) -> None:
    server = Rfc2136Server(
        keyring,
        StubDispatcher(),
        DataPlaneMetrics(registry=CollectorRegistry()),
        host="127.0.0.1",
        port=0,
    )
    # Read each state into a fresh local: the property flips via the running
    # serve task, which the type checker cannot model, so a persistent member
    # narrowing must not leak across the transitions.
    before_bind = server.is_accepting
    ready = asyncio.Event()
    task = asyncio.create_task(server.serve(ready=ready))
    await asyncio.wait_for(ready.wait(), timeout=5.0)
    after_bind = server.is_accepting
    server.stop_accepting()
    after_stop = server.is_accepting
    await _cancel(task)
    after_close = server.is_accepting

    assert (before_bind, after_bind, after_stop, after_close) == (
        False,  # not yet bound
        True,  # both sockets bound -> ready
        False,  # draining
        False,  # closed
    )


async def test_drain_awaits_in_flight_dispatch(keyring: Keyring, keyname: str) -> None:
    dispatcher = BlockingDispatcher()
    server, task = await _serve_with(dispatcher, keyring)
    try:
        wire = _signed_update(keyring, keyname).to_wire()
        reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
        writer.write(struct.pack("!H", len(wire)) + wire)
        await writer.drain()
        await asyncio.wait_for(dispatcher.entered.wait(), timeout=5.0)

        server.stop_accepting()
        drain_task = asyncio.create_task(server.drain(5.0))
        await asyncio.sleep(0.05)
        assert not drain_task.done()  # blocked on the in-flight dispatch

        dispatcher.release.set()
        await asyncio.wait_for(drain_task, timeout=5.0)
        assert dispatcher.completed == 1  # the in-flight challenge finished

        header = await asyncio.wait_for(reader.readexactly(2), timeout=5.0)
        (length,) = struct.unpack("!H", header)
        reply = await asyncio.wait_for(reader.readexactly(length), timeout=5.0)
        assert reply[3] & 0x0F == dns.rcode.NOERROR  # reply delivered before close
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    finally:
        await _cancel(task)


async def test_drain_is_bounded_and_cancels_stragglers(
    keyring: Keyring, keyname: str
) -> None:
    dispatcher = BlockingDispatcher()  # never released -> a hung dispatch
    server, task = await _serve_with(dispatcher, keyring)
    try:
        wire = _signed_update(keyring, keyname).to_wire()
        reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
        writer.write(struct.pack("!H", len(wire)) + wire)
        await writer.drain()
        await asyncio.wait_for(dispatcher.entered.wait(), timeout=5.0)

        server.stop_accepting()
        loop = asyncio.get_running_loop()
        started = loop.time()
        await server.drain(0.2)  # bounded — must not wait on the hung dispatch
        assert loop.time() - started < 2.0  # returned promptly
        assert dispatcher.completed == 0  # straggler cancelled, never completed
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    finally:
        await _cancel(task)


async def test_stop_accepting_refuses_new_tcp_connection(
    running_server: Rfc2136Server,
) -> None:
    running_server.stop_accepting()
    reader, writer = await asyncio.open_connection("127.0.0.1", running_server.port)
    # The server accepts then immediately closes a connection opened while
    # draining: the client observes EOF (or a reset) and never a framed reply.
    refused = False
    try:
        refused = await asyncio.wait_for(reader.read(1), timeout=2.0) == b""
    except (ConnectionError, asyncio.IncompleteReadError):
        refused = True
    assert refused
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()


async def test_stop_accepting_drops_new_udp_datagram(
    running_server: Rfc2136Server, keyring: Keyring, keyname: str
) -> None:
    running_server.stop_accepting()
    with pytest.raises(dns.exception.Timeout):
        await asyncio.to_thread(
            dns.query.udp,
            _signed_update(keyring, keyname),
            "127.0.0.1",
            0.5,  # short timeout: no reply arrives while draining
            running_server.port,
        )
