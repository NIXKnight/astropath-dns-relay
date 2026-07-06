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

"""RFC2136 UDP + TCP listener (SPEC §3.11, HIGH-3, HIGH-11).

The UDP ``datagram_received`` callback is **synchronous** and must never await
(SPEC §3.11 / §2.3): it hands each packet to ``asyncio.create_task`` and returns
immediately, so provider HTTP calls never block the event loop inside the
callback. TCP framing (RFC7766 2-byte length prefix) is added in T-M1-12.

The host/port are configurable so an external contract-test harness (miekg/dns)
can target the same listener. Malformed packets are dropped; the listener never
crashes on bad input (SPEC §3.12).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import dns.name
import dns.tsig

from astropath.data_plane.protocol import ChallengeDispatcher, handle_query
from astropath.observability import DataPlaneMetrics

__all__ = ["Rfc2136Server"]

log = logging.getLogger("astropath.data_plane.server")

Keyring = dict[dns.name.Name, dns.tsig.Key]


class _UdpProtocol(asyncio.DatagramProtocol):
    """UDP datagram protocol: sync callback hands off to a task (SPEC §3.11)."""

    def __init__(
        self,
        keyring: Keyring,
        dispatcher: ChallengeDispatcher,
        metrics: DataPlaneMetrics,
    ) -> None:
        self._keyring = keyring
        self._dispatcher = dispatcher
        self._metrics = metrics
        self._transport: asyncio.DatagramTransport | None = None
        self._tasks: set[asyncio.Task[None]] = set()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.DatagramTransport)
        self._transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str | Any, int]) -> None:
        # SYNC callback — MUST NOT await. Hand the packet off and return, so a
        # provider HTTP call never runs inline and blocks the event loop.
        task = asyncio.create_task(self._handle(bytes(data), addr))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _handle(self, data: bytes, addr: tuple[str | Any, int]) -> None:
        try:
            reply = await handle_query(
                data,
                self._keyring,
                self._dispatcher,
                source=str(addr[0]),
                metrics=self._metrics,
            )
        except Exception:  # never let one packet crash the listener
            log.exception("udp_handler_error", extra={"source": str(addr[0])})
            return
        if reply is not None and self._transport is not None:
            self._transport.sendto(reply, addr)


class Rfc2136Server:
    """RFC2136 UDP (and, from T-M1-12, TCP) listener for TSIG-signed UPDATE."""

    def __init__(
        self,
        keyring: Keyring,
        dispatcher: ChallengeDispatcher,
        metrics: DataPlaneMetrics,
        *,
        host: str,
        port: int,
    ) -> None:
        self._keyring = keyring
        self._dispatcher = dispatcher
        self._metrics = metrics
        self._host = host
        self._port = port
        self._udp_transport: asyncio.DatagramTransport | None = None

    @property
    def port(self) -> int:
        """The bound port (resolved when ``port=0`` was requested)."""
        return self._port

    async def serve(self, *, ready: asyncio.Event | None = None) -> None:
        """Bind the UDP listener and serve until cancelled (supervisor-driven)."""
        loop = asyncio.get_running_loop()
        self._udp_transport, _protocol = await loop.create_datagram_endpoint(
            lambda: _UdpProtocol(self._keyring, self._dispatcher, self._metrics),
            local_addr=(self._host, self._port),
        )
        sockname = self._udp_transport.get_extra_info("sockname")
        if sockname is not None:
            self._port = int(sockname[1])

        if ready is not None:
            ready.set()
        try:
            await asyncio.Event().wait()  # serve until the task is cancelled
        finally:
            self.close()

    def close(self) -> None:
        if self._udp_transport is not None:
            self._udp_transport.close()
            self._udp_transport = None
