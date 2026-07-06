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

"""Acceptance: inbound TSIG exception family (T-TEST-03).

BLOCKER-1 + HIGH-2 + HIGH-3. Every inbound-TSIG failure class is forced and the
observable contract is asserted: the reply rcode is NOTAUTH, a signable failure
carries the right TSIG error field (16 BADSIG / 17 BADKEY / 18 BADTIME), an
unknown key yields an unsigned reply, and — the crux — no auth failure ever
reaches the dispatcher. The response-side ``Peer*`` classes are never caught.
"""

from __future__ import annotations

import base64
import struct

import dns.message
import dns.name
import dns.rcode
import dns.rdata
import dns.rdatatype
import dns.rdtypes.ANY.TSIG
import dns.tsig
import dns.update
import dns.wire
import pytest
from prometheus_client import CollectorRegistry

from astropath.data_plane.protocol import handle_query
from astropath.observability import DataPlaneMetrics

Keyring = dict[dns.name.Name, dns.tsig.Key]

# A client secret that deliberately differs from the server fixture's secret.
_WRONG_SECRET = base64.b64encode(b"z" * 32).decode()


class RecordingDispatcher:
    """Fails the test's premise if ever called: auth must gate before dispatch."""

    def __init__(self) -> None:
        self.calls: list[dns.update.UpdateMessage] = []

    async def dispatch(
        self, msg: dns.update.UpdateMessage, *, source: str
    ) -> dns.rcode.Rcode:
        self.calls.append(msg)
        return dns.rcode.NOERROR


def _fresh() -> tuple[CollectorRegistry, DataPlaneMetrics]:
    reg = CollectorRegistry()
    return reg, DataPlaneMetrics(registry=reg)


def _signed_update(
    sign_keyring: Keyring, keyname: str, algorithm: dns.name.Name
) -> bytes:
    update = dns.update.UpdateMessage(
        "example.com.",
        keyname=dns.name.from_text(keyname),
        keyring=sign_keyring,
        keyalgorithm=algorithm,
    )
    update.add("_acme-challenge.example.com.", 300, "TXT", "tok")
    return update.to_wire()


def _keyed(name: str, secret: str, algorithm: dns.name.Name) -> Keyring:
    return {dns.name.from_text(name): dns.tsig.Key(name, secret, algorithm)}


def _rcode_of(wire: bytes) -> int:
    (flags,) = struct.unpack("!H", wire[2:4])
    return int(flags) & 0xF


def _reply_tsig(wire: bytes) -> dns.rdtypes.ANY.TSIG.TSIG | None:
    """Extract the reply's TSIG rdata (to read its error field + MAC)."""
    parser = dns.wire.Parser(wire)
    _id, _flags, qd, an, ns, ar = struct.unpack("!HHHHHH", parser.get_bytes(12))
    for _ in range(qd):
        parser.get_name()
        parser.get_struct("!HH")
    for _ in range(an + ns + ar):
        parser.get_name()
        rdtype, rdclass, _ttl, rdlen = parser.get_struct("!HHIH")
        with parser.restrict_to(rdlen):
            if rdtype == dns.rdatatype.TSIG:
                rdata = dns.rdata.from_wire_parser(rdclass, rdtype, parser, None)
                assert isinstance(rdata, dns.rdtypes.ANY.TSIG.TSIG)
                return rdata
            parser.get_bytes(rdlen)
    return None


async def _handle(wire: bytes, keyring: Keyring) -> tuple[bytes, RecordingDispatcher]:
    _reg, metrics = _fresh()
    dispatcher = RecordingDispatcher()
    reply = await handle_query(
        wire, keyring, dispatcher, source="1.2.3.4", metrics=metrics
    )
    assert reply is not None
    return reply, dispatcher


async def test_valid_signature_is_the_only_thing_that_dispatches(
    keyring: Keyring,
) -> None:
    """Positive control: a correctly-signed UPDATE does reach dispatch."""
    wire = _signed_update(keyring, "cm-key.", dns.tsig.HMAC_SHA256)
    _reply, dispatcher = await _handle(wire, keyring)
    assert len(dispatcher.calls) == 1


async def test_unknown_key_is_notauth_unsigned_and_not_dispatched(
    keyring: Keyring,
) -> None:
    wire = _signed_update(
        _keyed("other-key.", _WRONG_SECRET, dns.tsig.HMAC_SHA256),
        "other-key.",
        dns.tsig.HMAC_SHA256,
    )
    reply, dispatcher = await _handle(wire, keyring)

    assert _rcode_of(reply) == dns.rcode.NOTAUTH
    assert _reply_tsig(reply) is None  # no server key context -> cannot sign
    assert dispatcher.calls == []


@pytest.mark.parametrize(
    ("algorithm", "secret", "expected_error"),
    [
        (dns.tsig.HMAC_SHA256, _WRONG_SECRET, dns.rcode.BADSIG),  # 16: bad MAC
        (dns.tsig.HMAC_SHA512, _WRONG_SECRET, dns.rcode.BADKEY),  # 17: bad algorithm
    ],
)
async def test_signable_failure_is_signed_with_tsig_error(
    keyring: Keyring,
    algorithm: dns.name.Name,
    secret: str,
    expected_error: int,
) -> None:
    wire = _signed_update(_keyed("cm-key.", secret, algorithm), "cm-key.", algorithm)
    reply, dispatcher = await _handle(wire, keyring)

    assert _rcode_of(reply) == dns.rcode.NOTAUTH
    tsig = _reply_tsig(reply)
    assert tsig is not None  # error reply is TSIG-signed
    assert tsig.error == expected_error
    assert len(tsig.mac) == 32  # HMAC-SHA256 MAC present on the reply
    assert dispatcher.calls == []


async def test_bad_time_reply_is_signed_with_error_18(
    keyring: Keyring, monkeypatch: pytest.MonkeyPatch
) -> None:
    import time as _time

    wire = _signed_update(keyring, "cm-key.", dns.tsig.HMAC_SHA256)  # validly signed
    real_time = _time.time  # capture before patching to avoid recursion
    monkeypatch.setattr("dns.message.time.time", lambda: real_time() + 100_000)

    reply, dispatcher = await _handle(wire, keyring)

    assert _rcode_of(reply) == dns.rcode.NOTAUTH
    tsig = _reply_tsig(reply)
    assert tsig is not None
    assert tsig.error == dns.rcode.BADTIME  # 18
    assert dispatcher.calls == []


async def test_no_inbound_auth_failure_ever_reaches_dispatch(keyring: Keyring) -> None:
    """The BLOCKER-1 invariant, swept across the whole failure family."""
    failing_wires = [
        _signed_update(
            _keyed("other-key.", _WRONG_SECRET, dns.tsig.HMAC_SHA256),
            "other-key.",
            dns.tsig.HMAC_SHA256,
        ),  # unknown key
        _signed_update(
            _keyed("cm-key.", _WRONG_SECRET, dns.tsig.HMAC_SHA256),
            "cm-key.",
            dns.tsig.HMAC_SHA256,
        ),  # bad signature
        _signed_update(
            _keyed("cm-key.", _WRONG_SECRET, dns.tsig.HMAC_SHA512),
            "cm-key.",
            dns.tsig.HMAC_SHA512,
        ),  # bad algorithm -> badkey
        dns.update.UpdateMessage("example.com.").to_wire(),  # unsigned (absent TSIG)
    ]
    for wire in failing_wires:
        _reply, dispatcher = await _handle(wire, keyring)
        assert dispatcher.calls == []


def test_peer_response_side_classes_are_never_caught() -> None:
    """SPEC §3.3: ``Peer*`` are response-side; the inbound gate must not catch them.

    Verified two ways: the pipeline source references no ``Peer*`` class, and the
    caught server-side classes are not superclasses of their ``Peer*`` cousins, so
    the ``except`` clauses cannot swallow a peer error even by inheritance.
    """
    import inspect

    import astropath.data_plane.protocol as protocol

    source = inspect.getsource(protocol)
    for name in ("PeerBadKey", "PeerBadSignature", "PeerBadTime", "PeerBadTruncation"):
        assert name not in source

    assert not issubclass(dns.tsig.PeerBadSignature, dns.tsig.BadSignature)
    assert not issubclass(dns.tsig.PeerBadKey, dns.tsig.BadKey)
