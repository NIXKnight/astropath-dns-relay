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

import base64
import struct
from collections.abc import Callable

import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.tsig
import dns.update
import pytest
from prometheus_client import CollectorRegistry

from astropath.data_plane.protocol import handle_query
from astropath.observability import DataPlaneMetrics

Keyring = dict[dns.name.Name, dns.tsig.Key]
UpdateBuilder = Callable[..., bytes]

# A client secret that deliberately differs from the server fixture's secret.
_MISMATCHED_SECRET = base64.b64encode(b"z" * 32).decode()


def _client_signed_update(
    sign_keyring: Keyring, keyname: str, algorithm: dns.name.Name
) -> bytes:
    u = dns.update.UpdateMessage(
        "example.com.",
        keyname=dns.name.from_text(keyname),
        keyring=sign_keyring,
        keyalgorithm=algorithm,
    )
    u.add("_acme-challenge.example.com.", 300, "TXT", "tok")
    return u.to_wire()


def _fresh_metrics() -> tuple[CollectorRegistry, DataPlaneMetrics]:
    reg = CollectorRegistry()
    return reg, DataPlaneMetrics(registry=reg)


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


def _signed_query(keyring: Keyring, keyname: str, rdtype: str = "SOA") -> bytes:
    query = dns.message.make_query("example.com.", rdtype)
    query.use_tsig(keyring, keyname=dns.name.from_text(keyname))
    return query.to_wire()


async def test_non_update_opcode_refused_and_not_dispatched(
    keyring: Keyring,
    keyname: str,
    metrics: DataPlaneMetrics,
) -> None:
    """T-M1-07: a signed SOA QUERY is REFUSED, never dispatched (no SOA in M1)."""
    dispatcher = FakeDispatcher()

    reply = await handle_query(
        _signed_query(keyring, keyname),
        keyring,
        dispatcher,
        source="10.0.0.1",
        metrics=metrics,
    )

    assert reply is not None
    assert rcode_of(reply) == dns.rcode.REFUSED
    assert dispatcher.calls == []


def test_protocol_module_has_no_soa_handler() -> None:
    """No SOA-answering symbol exists in the pipeline (SPEC §3.7, HIGH-4)."""
    import astropath.data_plane.protocol as protocol

    assert not any("soa" in name.lower() for name in dir(protocol))


async def test_success_reply_is_tsig_signed(
    keyring: Keyring,
    keyname: str,
    metrics: DataPlaneMetrics,
) -> None:
    """T-M1-04: the success reply auto-signs; a client verifies it.

    Built inline so the client message retains its request MAC, which the client
    needs to verify the reply TSIG.
    """
    client = dns.update.UpdateMessage(
        "example.com.",
        keyname=dns.name.from_text(keyname),
        keyring=keyring,
        keyalgorithm=dns.tsig.HMAC_SHA256,
    )
    client.add("_acme-challenge.example.com.", 300, "TXT", "tok")
    wire = client.to_wire()

    reply = await handle_query(
        wire,
        keyring,
        FakeDispatcher(rcode=dns.rcode.NOERROR),
        source="10.0.0.1",
        metrics=metrics,
    )
    assert reply is not None

    verified = dns.message.from_wire(reply, keyring=keyring, request_mac=client.mac)
    assert verified.had_tsig is True  # reply carries a valid TSIG
    assert verified.opcode() == dns.opcode.UPDATE  # opcode preserved
    assert verified.rcode() == dns.rcode.NOERROR


# --------------------------------------------------------------------------- #
# T-M1-03: inbound TSIG exception family -> NOTAUTH + metric reason
# --------------------------------------------------------------------------- #
async def test_unknown_key_notauth_and_metric(keyring: Keyring) -> None:
    reg, m = _fresh_metrics()
    other = {
        dns.name.from_text("other-key."): dns.tsig.Key(
            "other-key.", _MISMATCHED_SECRET, dns.tsig.HMAC_SHA256
        )
    }
    wire = _client_signed_update(other, "other-key.", dns.tsig.HMAC_SHA256)

    reply = await handle_query(
        wire, keyring, FakeDispatcher(), source="1.2.3.4", metrics=m
    )
    assert reply is not None
    assert rcode_of(reply) == dns.rcode.NOTAUTH
    assert (
        reg.get_sample_value("astropath_tsig_failures_total", {"reason": "unknownkey"})
        == 1.0
    )


async def test_bad_signature_notauth_and_metric(keyring: Keyring) -> None:
    reg, m = _fresh_metrics()
    wrong = {
        dns.name.from_text("cm-key."): dns.tsig.Key(
            "cm-key.", _MISMATCHED_SECRET, dns.tsig.HMAC_SHA256
        )
    }
    wire = _client_signed_update(wrong, "cm-key.", dns.tsig.HMAC_SHA256)

    reply = await handle_query(
        wire, keyring, FakeDispatcher(), source="1.2.3.4", metrics=m
    )
    assert reply is not None
    assert rcode_of(reply) == dns.rcode.NOTAUTH
    assert (
        reg.get_sample_value("astropath_tsig_failures_total", {"reason": "badsig"})
        == 1.0
    )


async def test_bad_algorithm_maps_to_badkey_metric(keyring: Keyring) -> None:
    reg, m = _fresh_metrics()
    sha512 = {
        dns.name.from_text("cm-key."): dns.tsig.Key(
            "cm-key.", _MISMATCHED_SECRET, dns.tsig.HMAC_SHA512
        )
    }
    wire = _client_signed_update(sha512, "cm-key.", dns.tsig.HMAC_SHA512)

    reply = await handle_query(
        wire, keyring, FakeDispatcher(), source="1.2.3.4", metrics=m
    )
    assert reply is not None
    assert rcode_of(reply) == dns.rcode.NOTAUTH
    assert (
        reg.get_sample_value("astropath_tsig_failures_total", {"reason": "badkey"})
        == 1.0
    )


async def test_bad_time_notauth_and_badtime_metric(
    keyring: Keyring,
    make_signed_update: UpdateBuilder,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import time as _time

    reg, m = _fresh_metrics()
    wire = make_signed_update()
    real_time = _time.time
    monkeypatch.setattr("dns.message.time.time", lambda: real_time() + 100_000)

    reply = await handle_query(
        wire, keyring, FakeDispatcher(), source="1.2.3.4", metrics=m
    )
    assert reply is not None
    assert rcode_of(reply) == dns.rcode.NOTAUTH
    assert (
        reg.get_sample_value("astropath_tsig_failures_total", {"reason": "badtime"})
        == 1.0
    )
    assert reg.get_sample_value("astropath_tsig_badtime_total") == 1.0


def test_peer_exception_classes_never_caught() -> None:
    """SPEC §3.3: Peer* classes are response-side only and must not be caught."""
    import inspect

    import astropath.data_plane.protocol as protocol

    source = inspect.getsource(protocol)
    for name in ("PeerBadKey", "PeerBadSignature", "PeerBadTime", "PeerBadTruncation"):
        assert name not in source
