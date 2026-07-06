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

"""RFC2136 wire-pipeline tests (T-M1-02.., SPEC §3)."""

from __future__ import annotations

import struct
from collections.abc import Callable

import dns.name
import dns.rcode
import dns.tsig
import dns.update

from astropath.data_plane.protocol import handle_query
from astropath.observability import DataPlaneMetrics

Keyring = dict[dns.name.Name, dns.tsig.Key]
UpdateBuilder = Callable[..., bytes]


class FakeDispatcher:
    """Records dispatch calls and returns a preset rcode."""

    def __init__(self, rcode: dns.rcode.Rcode = dns.rcode.NOERROR) -> None:
        self.rcode = rcode
        self.calls: list[dns.update.UpdateMessage] = []

    async def dispatch(
        self, msg: dns.update.UpdateMessage, *, source: str
    ) -> dns.rcode.Rcode:
        self.calls.append(msg)
        return self.rcode


def rcode_of(wire: bytes) -> int:
    """Read the basic rcode from a reply header (low 4 flag bits)."""
    (flags,) = struct.unpack("!H", wire[2:4])
    return int(flags) & 0xF


async def test_unsigned_update_rejected_notauth_and_not_dispatched(
    make_unsigned_update: UpdateBuilder,
    keyring: Keyring,
    metrics: DataPlaneMetrics,
) -> None:
    dispatcher = FakeDispatcher()

    reply = await handle_query(
        make_unsigned_update(),
        keyring,
        dispatcher,
        source="10.0.0.1",
        metrics=metrics,
    )

    assert reply is not None
    assert rcode_of(reply) == dns.rcode.NOTAUTH
    assert dispatcher.calls == []  # never dispatched an unsigned UPDATE


async def test_signed_update_is_dispatched(
    make_signed_update: UpdateBuilder,
    keyring: Keyring,
    metrics: DataPlaneMetrics,
) -> None:
    dispatcher = FakeDispatcher(rcode=dns.rcode.NOERROR)

    reply = await handle_query(
        make_signed_update(),
        keyring,
        dispatcher,
        source="10.0.0.1",
        metrics=metrics,
    )

    assert reply is not None
    assert rcode_of(reply) == dns.rcode.NOERROR
    assert len(dispatcher.calls) == 1
    assert isinstance(dispatcher.calls[0], dns.update.UpdateMessage)
