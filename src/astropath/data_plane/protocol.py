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

"""RFC2136 wire pipeline: parse, auth gate, dispatch, reply (SPEC §3).

:func:`handle_query` is the pure wire→wire heart of the data plane, independent
of the UDP/TCP transport (:mod:`astropath.data_plane.server`). It parses and
verifies the inbound message, enforces the TSIG auth gate (BLOCKER-1), routes by
opcode, hands UPDATEs to the injected dispatcher, and builds the reply.

Auth gate (SPEC §3.2): ``dns.message.from_wire`` verifies TSIG only when a TSIG
RR is physically present — an unsigned UPDATE parses cleanly with
``had_tsig is False``. The server MUST assert ``had_tsig`` before dispatch and
answer an unsigned UPDATE with NOTAUTH, never dispatching it.
"""

from __future__ import annotations

from typing import Protocol

import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.tsig
import dns.update

from astropath.observability import TSIG_ABSENT, DataPlaneMetrics

__all__ = ["ChallengeDispatcher", "handle_query"]


class ChallengeDispatcher(Protocol):
    """Structural interface the pipeline calls for a verified UPDATE (§3, §4).

    Returns the reply rcode: NOERROR on success, REFUSED on a write-surface or
    unknown-zone rejection, SERVFAIL on provider failure (SPEC §3.6).
    """

    async def dispatch(
        self, msg: dns.update.UpdateMessage, *, source: str
    ) -> dns.rcode.Rcode: ...


def _reply(query: dns.message.Message, rcode: dns.rcode.Rcode) -> bytes:
    """Build a reply for ``query`` with ``rcode``.

    ``make_response`` auto-signs when the query carried verified TSIG context
    (``query.had_tsig and query.keyring``); an unsigned query yields a plain
    reply. The request id and question/ZONE context are preserved natively.
    """
    response = dns.message.make_response(query)
    response.set_rcode(rcode)
    return response.to_wire()


async def handle_query(
    wire: bytes,
    keyring: dict[dns.name.Name, dns.tsig.Key],
    dispatcher: ChallengeDispatcher,
    *,
    source: str,
    metrics: DataPlaneMetrics,
) -> bytes | None:
    """Process one inbound DNS message; return the reply wire (or ``None``).

    A ``None`` return means "drop" (no answerable reply). The auth gate rejects
    an unsigned UPDATE with NOTAUTH and never dispatches it.
    """
    msg = dns.message.from_wire(wire, keyring=keyring)

    # Auth gate (BLOCKER-1): from_wire does NOT raise on an ABSENT TSIG.
    if not msg.had_tsig:
        metrics.record_tsig_failure(TSIG_ABSENT)
        return _reply(msg, dns.rcode.NOTAUTH)  # unsigned -> plain NOTAUTH, no dispatch

    if msg.opcode() != dns.opcode.UPDATE:
        return _reply(msg, dns.rcode.REFUSED)  # non-UPDATE -> REFUSED (signed)

    assert isinstance(msg, dns.update.UpdateMessage)
    rcode = await dispatcher.dispatch(msg, source=source)
    return _reply(msg, rcode)
