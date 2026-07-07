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

import struct
from dataclasses import dataclass
from typing import Protocol

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.rdata
import dns.rdatatype
import dns.rdtypes.ANY.TSIG
import dns.tsig
import dns.update
import dns.wire

from astropath.correlation import correlation_scope, new_dns_correlation_id
from astropath.observability import (
    TSIG_ABSENT,
    TSIG_BADKEY,
    TSIG_BADSIG,
    TSIG_BADTIME,
    TSIG_UNKNOWNKEY,
    DataPlaneMetrics,
)

__all__ = ["ChallengeDispatcher", "handle_query"]


@dataclass(frozen=True)
class _TsigWire:
    """Context recovered directly from the wire (SPEC §3.5).

    Needed because a raised inbound-TSIG failure discards the parsed query and a
    keyring-less re-parse raises ``UnknownTSIGKey`` — so id/opcode/keyname/mac
    for the signed error reply are read straight from the bytes.
    """

    id: int
    opcode: int
    keyname: dns.name.Name | None
    mac: bytes | None


def _extract_tsig_context(wire: bytes) -> _TsigWire | None:
    """Recover id/opcode and (if present) the TSIG keyname + MAC from the wire.

    Returns ``None`` when the packet cannot be parsed enough to answer (no usable
    id) — the caller then drops it (SPEC §3.12).
    """
    try:
        msg_id, flags, qd, an, ns, ar = struct.unpack(
            "!HHHHHH", dns.wire.Parser(wire).get_bytes(12)
        )
        parser = dns.wire.Parser(wire)
        parser.get_bytes(12)
        for _ in range(qd):
            parser.get_name()
            parser.get_struct("!HH")
        keyname: dns.name.Name | None = None
        mac: bytes | None = None
        for _ in range(an + ns + ar):
            name = parser.get_name()
            rdtype, rdclass, _ttl, rdlen = parser.get_struct("!HHIH")
            with parser.restrict_to(rdlen):
                if rdtype == dns.rdatatype.TSIG:
                    rdata = dns.rdata.from_wire_parser(rdclass, rdtype, parser, None)
                    if isinstance(rdata, dns.rdtypes.ANY.TSIG.TSIG):
                        keyname = name
                        mac = rdata.mac
                else:
                    parser.get_bytes(rdlen)
    except (dns.exception.DNSException, struct.error, ValueError, IndexError):
        return None
    return _TsigWire(id=msg_id, opcode=(flags >> 11) & 0xF, keyname=keyname, mac=mac)


def _reply_from_ctx(ctx: _TsigWire, rcode: dns.rcode.Rcode) -> dns.message.QueryMessage:
    """Build a bare response echoing the request id + opcode with ``rcode``."""
    response = dns.message.QueryMessage(id=ctx.id)
    response.flags = dns.flags.QR
    response.set_opcode(dns.opcode.Opcode(ctx.opcode))
    response.set_rcode(rcode)
    return response


def _plain_error_reply(wire: bytes, rcode: dns.rcode.Rcode) -> bytes | None:
    """Build an unsigned reply preserving the request id and opcode (§3.12).

    Used when no key context is available to sign (absent/unknown key). Returns
    ``None`` if the request id cannot be recovered (drop).
    """
    ctx = _extract_tsig_context(wire)
    if ctx is None:
        return None
    return _reply_from_ctx(ctx, rcode).to_wire()


def _signed_error_reply(
    wire: bytes,
    keyring: dict[dns.name.Name, dns.tsig.Key],
    rcode: dns.rcode.Rcode,
    *,
    tsig_error: int,
) -> bytes | None:
    """Build a TSIG-signed error reply (SPEC §3.5).

    from_wire raised, so no keyring-bound query exists — the id/keyname/mac are
    recovered from the wire and the reply is signed manually with the server's
    Key (bound algorithm), carrying the TSIG error field (16/17/18). Falls back
    to an unsigned reply when the key is unrecoverable; drops if no id.
    """
    ctx = _extract_tsig_context(wire)
    if ctx is None:
        return None
    if ctx.keyname is None or ctx.mac is None:
        return _reply_from_ctx(ctx, rcode).to_wire()
    key = keyring.get(ctx.keyname)
    if key is None:
        return _reply_from_ctx(ctx, rcode).to_wire()

    response = _reply_from_ctx(ctx, rcode)
    response.use_tsig(key, fudge=300, original_id=ctx.id, tsig_error=tsig_error)
    response.request_mac = ctx.mac  # digest covers the client's request MAC
    return response.to_wire()


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
    """Process one inbound DNS message under a fresh correlation scope (T-M6-03).

    A ``None`` return means "drop" (no answerable reply). Every log record emitted
    during parse → auth gate → dispatch → provider → audit shares one correlation
    id derived from the 16-bit DNS request id (SPEC §11.4), so a stuck challenge is
    traceable end to end.
    """
    request_id = int.from_bytes(wire[:2], "big") if len(wire) >= 2 else 0
    with correlation_scope(new_dns_correlation_id(request_id)):
        return await _process_query(
            wire, keyring, dispatcher, source=source, metrics=metrics
        )


async def _process_query(
    wire: bytes,
    keyring: dict[dns.name.Name, dns.tsig.Key],
    dispatcher: ChallengeDispatcher,
    *,
    source: str,
    metrics: DataPlaneMetrics,
) -> bytes | None:
    """Parse, auth-gate, route, and reply (the wire→wire heart of the pipeline).

    The auth gate rejects an unsigned UPDATE with NOTAUTH and never dispatches it.
    Runs inside the correlation scope opened by :func:`handle_query`.
    """
    # Inbound TSIG failure family (SPEC §3.3). Catch exactly these server-side
    # classes; BadAlgorithm (bound-algorithm mismatch) is folded into BADKEY.
    # Never catch dns.tsig.Peer* — those are response-side only.
    try:
        msg = dns.message.from_wire(wire, keyring=keyring)
    except dns.message.UnknownTSIGKey:
        metrics.record_tsig_failure(TSIG_UNKNOWNKEY)
        return _plain_error_reply(wire, dns.rcode.NOTAUTH)  # unknown key: cannot sign
    except dns.tsig.BadSignature:
        metrics.record_tsig_failure(TSIG_BADSIG)
        return _signed_error_reply(
            wire, keyring, dns.rcode.NOTAUTH, tsig_error=dns.rcode.BADSIG
        )
    except dns.tsig.BadTime:
        metrics.record_tsig_failure(TSIG_BADTIME)
        return _signed_error_reply(
            wire, keyring, dns.rcode.NOTAUTH, tsig_error=dns.rcode.BADTIME
        )
    except (dns.tsig.BadKey, dns.tsig.BadAlgorithm):
        metrics.record_tsig_failure(TSIG_BADKEY)
        return _signed_error_reply(
            wire, keyring, dns.rcode.NOTAUTH, tsig_error=dns.rcode.BADKEY
        )
    except dns.exception.DNSException:
        # Malformed / unparseable packet with no answerable context (SPEC §3.12):
        # drop it. The listener closes the TCP connection / ignores the datagram.
        return None

    # Auth gate (BLOCKER-1): from_wire does NOT raise on an ABSENT TSIG.
    if not msg.had_tsig:
        metrics.record_tsig_failure(TSIG_ABSENT)
        return _reply(msg, dns.rcode.NOTAUTH)  # unsigned -> plain NOTAUTH, no dispatch

    # Opcode routing (SPEC §3.7, HIGH-4): UPDATE is dispatched; QUERY and every
    # other opcode get REFUSED. There is deliberately NO SOA answering in M1 —
    # cert-manager's FindZoneByFqdn SOA probe goes to the recursive resolvers,
    # never to astropath, so a half-correct SOA handler would be harmful.
    if msg.opcode() != dns.opcode.UPDATE:
        return _reply(msg, dns.rcode.REFUSED)  # non-UPDATE -> REFUSED (signed)

    assert isinstance(msg, dns.update.UpdateMessage)
    rcode = await dispatcher.dispatch(msg, source=source)
    return _reply(msg, rcode)
