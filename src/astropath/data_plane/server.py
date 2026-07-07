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
callback. TCP is mandatory (TSIG-signed UPDATEs can exceed 512 bytes) with the
RFC7766 2-byte big-endian length prefix framing.

The host/port are configurable so an external contract-test harness (miekg/dns)
can target the same listener. Malformed packets are dropped on UDP / the TCP
connection is closed; the listener never crashes on bad input (SPEC §3.12).

Graceful shutdown (SPEC §2/§3, T-M6-05): :meth:`Rfc2136Server.stop_accepting`
flips the server to not-ready and drops new work, :meth:`Rfc2136Server.drain`
awaits the in-flight UDP/TCP dispatches under a bounded timeout (cancelling
stragglers), and :meth:`Rfc2136Server.close` releases the sockets last —
``main()`` sequences these around DB-pool and HTTP-client disposal.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import struct
from collections.abc import Callable
from typing import Any

import dns.name
import dns.tsig

from astropath.data_plane.protocol import ChallengeDispatcher, handle_query
from astropath.observability import DataPlaneMetrics

__all__ = ["Rfc2136Server"]

log = logging.getLogger("astropath.data_plane.server")

Keyring = dict[dns.name.Name, dns.tsig.Key]

#: A zero-arg callable returning the current keyring. The management plane (M3)
#: supplies ``lambda: cache.keyring`` so a TSIG key added via the API converges to
#: the data plane on the next request without a restart (T-M3-16); the file-based
#: M1 path passes a static dict, wrapped here as a constant provider.
KeyringProvider = Callable[[], Keyring]


def _as_provider(keyring: Keyring | KeyringProvider) -> KeyringProvider:
    """Normalize a static keyring or a provider to a provider callable."""
    if callable(keyring):
        return keyring
    return lambda: keyring


class _UdpProtocol(asyncio.DatagramProtocol):
    """UDP datagram protocol: sync callback hands off to a task (SPEC §3.11)."""

    def __init__(
        self,
        keyring: KeyringProvider,
        dispatcher: ChallengeDispatcher,
        metrics: DataPlaneMetrics,
    ) -> None:
        self._keyring = keyring  # a provider; resolved per datagram
        self._dispatcher = dispatcher
        self._metrics = metrics
        self._transport: asyncio.DatagramTransport | None = None
        self._tasks: set[asyncio.Task[None]] = set()
        #: Flipped False by the server on graceful shutdown (SPEC §2/§3): new
        #: datagrams are dropped while in-flight handlers drain.
        self.accepting = True

    @property
    def inflight(self) -> set[asyncio.Task[None]]:
        """The in-flight per-datagram handler tasks (for the drain, T-M6-05)."""
        return self._tasks

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.DatagramTransport)
        self._transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str | Any, int]) -> None:
        # SYNC callback — MUST NOT await. Hand the packet off and return, so a
        # provider HTTP call never runs inline and blocks the event loop.
        if not self.accepting:
            return  # draining on shutdown: drop new datagrams (client retries)
        task = asyncio.create_task(self._handle(bytes(data), addr))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _handle(self, data: bytes, addr: tuple[str | Any, int]) -> None:
        try:
            reply = await handle_query(
                data,
                self._keyring(),  # resolve the current keyring per datagram (T-M3-16)
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
    """RFC2136 UDP + TCP listener for TSIG-signed DNS UPDATE (SPEC §3)."""

    def __init__(
        self,
        keyring: Keyring | KeyringProvider,
        dispatcher: ChallengeDispatcher,
        metrics: DataPlaneMetrics,
        *,
        host: str,
        port: int,
    ) -> None:
        self._keyring = _as_provider(keyring)
        self._dispatcher = dispatcher
        self._metrics = metrics
        self._host = host
        self._port = port
        self._udp_transport: asyncio.DatagramTransport | None = None
        self._udp_protocol: _UdpProtocol | None = None
        self._tcp_server: asyncio.Server | None = None
        self._tcp_conns: set[asyncio.Task[None]] = set()
        #: True only while both sockets are bound and taking new work. Drives
        #: per-plane readiness (T-M6-04) and the graceful-drain gate (T-M6-05).
        self._accepting = False

    @property
    def port(self) -> int:
        """The bound port (resolved when ``port=0`` was requested)."""
        return self._port

    @property
    def is_accepting(self) -> bool:
        """Whether both sockets are bound and the server is taking new work."""
        return self._accepting

    async def serve(self, *, ready: asyncio.Event | None = None) -> None:
        """Bind UDP + TCP and serve until cancelled (supervisor-driven)."""
        loop = asyncio.get_running_loop()
        self._udp_transport, self._udp_protocol = await loop.create_datagram_endpoint(
            lambda: _UdpProtocol(self._keyring, self._dispatcher, self._metrics),
            local_addr=(self._host, self._port),
        )
        sockname = self._udp_transport.get_extra_info("sockname")
        if sockname is not None:
            self._port = int(sockname[1])

        # Bind TCP on the same (now-resolved) port for >512-byte UPDATEs.
        self._tcp_server = await asyncio.start_server(
            self._handle_tcp, self._host, self._port
        )

        # Both sockets bound — take new work and report ready (no await between
        # the bind and this flag, so no datagram is processed while False).
        self._accepting = True
        if ready is not None:
            ready.set()
        try:
            await self._tcp_server.serve_forever()
        finally:
            self.close()

    def _is_draining(self) -> bool:
        """Whether graceful shutdown has begun (new work refused; SPEC §2/§3).

        Read via a method (not the attribute directly) so a truthiness check in
        one coroutine does not let the type checker assume the flag is constant
        across ``await`` points — ``stop_accepting`` flips it from ``main()``.
        """
        return not self._accepting

    def stop_accepting(self) -> None:
        """Stop taking new work; in-flight dispatches keep running (SPEC §2/§3).

        Flips readiness to not-ready and drops new UDP datagrams / refuses new TCP
        connections, without closing the sockets — :meth:`drain` then awaits the
        in-flight handlers and :meth:`close` releases the sockets last.
        """
        self._accepting = False
        if self._udp_protocol is not None:
            self._udp_protocol.accepting = False

    async def drain(self, timeout: float) -> None:
        """Await in-flight UDP + TCP dispatches, bounded by ``timeout`` (SPEC §2/§3).

        Stragglers still running past the deadline are cancelled so shutdown stays
        bounded (a hung provider call must not block the process from exiting).
        """
        current = asyncio.current_task()
        inflight = set(self._tcp_conns)
        if self._udp_protocol is not None:
            inflight |= self._udp_protocol.inflight
        inflight = {
            task for task in inflight if task is not current and not task.done()
        }
        if not inflight:
            return
        _done, pending = await asyncio.wait(inflight, timeout=timeout)
        for task in pending:
            task.cancel()  # bounded drain — force-stop stragglers past the deadline
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    def close(self) -> None:
        self._accepting = False
        if self._udp_transport is not None:
            self._udp_transport.close()
            self._udp_transport = None
        self._udp_protocol = None
        if self._tcp_server is not None:
            self._tcp_server.close()
            self._tcp_server = None

    async def _handle_tcp(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        source = str(peer[0]) if peer else "?"
        # Refuse a connection opened during shutdown; existing ones drain (§2/§3).
        if self._is_draining():
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            return
        conn = asyncio.current_task()
        if conn is not None:
            self._tcp_conns.add(conn)
            conn.add_done_callback(self._tcp_conns.discard)
        try:
            while True:
                header = await reader.readexactly(2)  # RFC7766 length prefix
                (length,) = struct.unpack("!H", header)
                payload = await reader.readexactly(length)
                try:
                    reply = await handle_query(
                        payload,
                        self._keyring(),  # current keyring per message (T-M3-16)
                        self._dispatcher,
                        source=source,
                        metrics=self._metrics,
                    )
                except Exception:
                    log.exception("tcp_handler_error", extra={"source": source})
                    break  # close the connection on an unexpected error
                if reply is None:
                    break  # malformed -> close the connection
                writer.write(struct.pack("!H", len(reply)) + reply)
                await writer.drain()
                if self._is_draining():
                    break  # draining: close after answering the in-flight message
        except asyncio.IncompleteReadError:
            pass  # peer closed mid-message
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
