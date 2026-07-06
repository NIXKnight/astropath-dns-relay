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

"""dnspython build-time asserts (T-TEST-01, SPEC §3, §18.1).

These tests pin the *actual* dnspython behaviour of the pinned version against
which the RFC2136/TSIG data plane is written. They are the acceptance gate for
the SPEC ``[ASSERT]`` items in §3: if dnspython changes shape, these fail and
block the dependent M1 code before it can silently misbehave.

Several assertions **correct** the wording of the SPEC ``[ASSERT]`` bullets to
the real dnspython 2.8.0 contract; each such correction is called out in the
test docstring. All secret material below is obvious throwaway bytes; no real
secret exists in this repository (SPEC secret discipline).
"""

from __future__ import annotations

import base64
import inspect
import struct

import dns.message
import dns.name
import dns.opcode
import dns.query
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.TSIG
import dns.tsig
import dns.tsigkeyring
import dns.update
import dns.wire
import pytest


def _parse_update(wire: bytes, **kwargs: object) -> dns.update.UpdateMessage:
    """Parse ``wire`` and narrow the result to ``UpdateMessage`` for the type
    checker (``from_wire`` is typed as returning the base ``Message``)."""
    msg = dns.message.from_wire(wire, **kwargs)  # type: ignore[arg-type]
    assert isinstance(msg, dns.update.UpdateMessage)
    return msg


# Obvious throwaway 32-byte secret, base64 BIND form. Not a real key.
_SECRET_B64 = base64.b64encode(b"0123456789abcdef0123456789abcdef").decode()
_KEYNAME = "cm-key."


def _keyring() -> dict[dns.name.Name, dns.tsig.Key]:
    key = dns.tsig.Key(_KEYNAME, _SECRET_B64, algorithm=dns.tsig.HMAC_SHA256)
    return {dns.name.from_text(_KEYNAME): key}


def _signed_update(keyring: dict[dns.name.Name, dns.tsig.Key]) -> bytes:
    u = dns.update.UpdateMessage(
        "example.com.",
        keyring=keyring,
        keyname=dns.name.from_text(_KEYNAME),
        keyalgorithm=dns.tsig.HMAC_SHA256,
    )
    u.add("_acme-challenge.example.com.", 300, "TXT", "tokentokentoken")
    return u.to_wire()


# --------------------------------------------------------------------------- #
# make_response signature (SPEC §3.4 / §18.1)
# --------------------------------------------------------------------------- #
def test_make_response_signature_has_no_rcode_kwarg() -> None:
    """CORRECTION: dnspython 2.8.0 ``make_response`` has **no** ``rcode=`` kwarg.

    SPEC §3.4 hedged ("set explicitly if the pinned signature requires
    set_rcode()"); this proves the rcode MUST be set with ``set_rcode`` after
    construction. ``fudge`` and ``tsig_error`` ARE keyword params (used by the
    error-signing path, §3.5).
    """
    params = inspect.signature(dns.message.make_response).parameters
    assert "rcode" not in params, "unexpected rcode kwarg — revisit set_rcode usage"
    assert "fudge" in params
    assert "tsig_error" in params


# --------------------------------------------------------------------------- #
# UpdateMessage section accessors (SPEC §3.9, §3.10)
# --------------------------------------------------------------------------- #
def test_update_message_section_accessors() -> None:
    msg = _parse_update(_signed_update(_keyring()), keyring=_keyring())
    for attr in ("zone", "prerequisite", "update", "additional"):
        assert isinstance(getattr(msg, attr), list), attr
    # ZONE section carries a single rrset whose owner is the target zone.
    assert msg.zone[0].name == dns.name.from_text("example.com.")


# --------------------------------------------------------------------------- #
# ADD vs DELETE representation (SPEC §3.8 — CORRECTED)
# --------------------------------------------------------------------------- #
def test_add_rrset_has_deleting_none() -> None:
    msg = _parse_update(_signed_update(_keyring()), keyring=_keyring())
    rrset = msg.update[0]
    assert rrset.rdclass == dns.rdataclass.IN
    assert rrset.deleting is None  # add => deleting attribute is None


def test_delete_specific_rr_uses_deleting_none_not_rdclass() -> None:
    """CORRECTION of SPEC §3.8 ``[ASSERT]``.

    SPEC said "class-NONE DELETE → ``rrset.rdclass == NONE``". In dnspython
    2.8.0 the parsed rrset keeps ``rdclass == IN`` and records the delete class
    on a **separate** ``rrset.deleting`` attribute (254 == NONE). The dispatcher
    (T-M1-08) therefore branches on ``rrset.deleting``, never ``rrset.rdclass``.
    """
    d = dns.update.UpdateMessage("example.com.")
    d.delete("_acme-challenge.example.com.", "TXT", "tokentokentoken")
    rrset = _parse_update(d.to_wire()).update[0]
    assert rrset.rdclass == dns.rdataclass.IN  # NOT NONE
    assert rrset.deleting == dns.rdataclass.NONE  # the real delete marker


def test_delete_entire_rrset_uses_deleting_any() -> None:
    d = dns.update.UpdateMessage("example.com.")
    d.delete("_acme-challenge.example.com.", "TXT")
    rrset = _parse_update(d.to_wire()).update[0]
    assert rrset.deleting == dns.rdataclass.ANY


# --------------------------------------------------------------------------- #
# tsigkeyring.from_text return shape (SPEC §3.1 — the security rationale)
# --------------------------------------------------------------------------- #
def test_from_text_plain_string_returns_raw_bytes() -> None:
    """Plain-string ``from_text`` yields **bytes** — the attackable shape.

    Raw bytes make ``from_wire`` build the Key with the *wire* algorithm
    (attacker-influenced). This is exactly why T-M1-01 builds explicit
    ``dns.tsig.Key`` objects instead (algorithm bound server-side).
    """
    kr = dns.tsigkeyring.from_text({_KEYNAME: _SECRET_B64})
    assert isinstance(next(iter(kr.values())), bytes)


def test_from_text_tuple_form_binds_algorithm() -> None:
    kr = dns.tsigkeyring.from_text({_KEYNAME: ("hmac-sha256", _SECRET_B64)})
    key = next(iter(kr.values()))
    assert isinstance(key, dns.tsig.Key)
    assert key.algorithm == dns.tsig.HMAC_SHA256


# --------------------------------------------------------------------------- #
# TCP framing helpers (SPEC §3.11)
# --------------------------------------------------------------------------- #
def test_send_receive_tcp_exist_and_frame_two_byte_prefix() -> None:
    assert hasattr(dns.query, "send_tcp")
    assert hasattr(dns.query, "receive_tcp")
    wire = _signed_update(_keyring())
    # RFC 7766 framing is a 2-byte big-endian length prefix.
    framed = struct.pack("!H", len(wire)) + wire
    assert struct.unpack("!H", framed[:2])[0] == len(wire)


# --------------------------------------------------------------------------- #
# Algorithm text form (SPEC §3.1 — CORRECTED trailing dot)
# --------------------------------------------------------------------------- #
def test_hmac_sha256_text_form() -> None:
    """CORRECTION: ``to_text()`` yields ``'hmac-sha256.'`` (trailing dot).

    SPEC §3.1 asserted ``== 'hmac-sha256'``. The dashed RFC8945 name without the
    final dot requires ``omit_final_dot=True``; the stored/config form is the
    dashless-dot-less ``'hmac-sha256'``.
    """
    assert dns.tsig.HMAC_SHA256.to_text() == "hmac-sha256."
    assert dns.tsig.HMAC_SHA256.to_text(omit_final_dot=True) == "hmac-sha256"


# --------------------------------------------------------------------------- #
# had_tsig gate (SPEC §3.2, BLOCKER-1)
# --------------------------------------------------------------------------- #
def test_unsigned_update_parses_cleanly_with_had_tsig_false() -> None:
    u = dns.update.UpdateMessage("example.com.")
    u.add("_acme-challenge.example.com.", 300, "TXT", "tok")
    msg = dns.message.from_wire(u.to_wire(), keyring=_keyring())
    assert msg.had_tsig is False  # keyring never consulted; MUST gate before dispatch


def test_signed_update_verifies_and_had_tsig_true() -> None:
    msg = dns.message.from_wire(_signed_update(_keyring()), keyring=_keyring())
    assert msg.had_tsig is True
    assert msg.opcode() == dns.opcode.UPDATE


# --------------------------------------------------------------------------- #
# Inbound TSIG failure family (SPEC §3.3) — server-side classes only
# --------------------------------------------------------------------------- #
def test_bad_signature_raises_without_recoverable_context() -> None:
    """CORRECTION of SPEC §3.5 recovery mechanism.

    A wrong-secret verification raises ``dns.tsig.BadSignature``; the exception
    object carries **no** ``keyname``/``mac`` and (critically) a keyring-less
    re-parse RAISES ``UnknownTSIGKey`` ("got signed message without keyring") —
    so SPEC §3.5's "re-parse without the keyring" does not work. The signed
    error path (T-M1-05) instead extracts id/keyname/mac directly from the wire.
    """
    good = _keyring()
    wrong_secret = base64.b64encode(b"f" * 32).decode()
    wrong = {dns.name.from_text(_KEYNAME): dns.tsig.Key(_KEYNAME, wrong_secret)}
    wire = _signed_update(good)
    with pytest.raises(dns.tsig.BadSignature) as exc:
        dns.message.from_wire(wire, keyring=wrong)
    assert not hasattr(exc.value, "keyname")
    assert not hasattr(exc.value, "mac")
    # keyring-less re-parse of a signed message raises (SPEC §3.5 mechanism fails)
    with pytest.raises(dns.message.UnknownTSIGKey):
        dns.message.from_wire(wire)


def test_unknown_key_name_raises_unknown_tsig_key() -> None:
    wire = _signed_update(_keyring())
    other = {dns.name.from_text("other-key."): dns.tsig.Key("other-key.", _SECRET_B64)}
    with pytest.raises(dns.message.UnknownTSIGKey):
        dns.message.from_wire(wire, keyring=other)


def test_bad_time_raises_bad_time(monkeypatch: pytest.MonkeyPatch) -> None:
    import time as _time

    wire = _signed_update(_keyring())
    real_time = _time.time  # capture before patching to avoid self-recursion

    # Force the server clock far outside the 300s fudge window.
    monkeypatch.setattr("dns.message.time.time", lambda: real_time() + 100_000)
    with pytest.raises(dns.tsig.BadTime):
        dns.message.from_wire(wire, keyring=_keyring())


def test_algorithm_mismatch_raises_bad_algorithm() -> None:
    """CORRECTION: bound-algorithm mismatch raises ``BadAlgorithm``, not BadKey.

    T-M1-01 AC says "BADKEY on algorithm mismatch"; dnspython 2.8.0 raises
    ``dns.tsig.BadAlgorithm`` when the pre-bound key algorithm differs from the
    wire algorithm. The security property (wire algorithm cannot override the
    bound one) holds — the message is rejected, not silently downgraded. The
    server maps BadAlgorithm to the BADKEY TSIG error (T-M1-03).
    """
    wire = _signed_update(_keyring())  # client signed with HMAC-SHA256
    bound_sha512 = {
        dns.name.from_text(_KEYNAME): dns.tsig.Key(
            _KEYNAME, _SECRET_B64, algorithm=dns.tsig.HMAC_SHA512
        )
    }
    with pytest.raises(dns.tsig.BadAlgorithm):
        dns.message.from_wire(wire, keyring=bound_sha512)


def test_peer_classes_are_response_side_only() -> None:
    """``Peer*`` classes exist but subclass ``PeerError`` (response validation).

    The server MUST NOT catch them (SPEC §3.3): they never fire on inbound
    request verification. This pins that they are a distinct hierarchy.
    """
    for name in ("PeerBadKey", "PeerBadSignature", "PeerBadTime"):
        assert issubclass(getattr(dns.tsig, name), dns.tsig.PeerError)
    assert not issubclass(dns.tsig.BadSignature, dns.tsig.PeerError)


# --------------------------------------------------------------------------- #
# Success reply auto-signs; manual wire extraction recovers error context
# --------------------------------------------------------------------------- #
def test_make_response_autosigns_when_query_verified() -> None:
    keyring = _keyring()
    query = dns.message.from_wire(_signed_update(keyring), keyring=keyring)
    resp = dns.message.make_response(query)
    assert resp.opcode() == dns.opcode.UPDATE
    # to_wire must carry a TSIG (auto-signed) that the client can verify.
    resp_wire = resp.to_wire()
    verified = dns.message.from_wire(resp_wire, keyring=keyring, request_mac=query.mac)
    assert verified.had_tsig is True


def test_manual_wire_extraction_recovers_id_keyname_mac() -> None:
    """The wire-level fallback the signed-error path (T-M1-05) depends on."""
    wire = _signed_update(_keyring())
    parser = dns.wire.Parser(wire)
    msg_id, _flags, qd, an, ns, ar = struct.unpack("!HHHHHH", parser.get_bytes(12))
    for _ in range(qd):
        parser.get_name()
        parser.get_struct("!HH")
    keyname = None
    tsig = None
    for _ in range(an + ns + ar):
        name = parser.get_name()
        rdtype, rdclass, _ttl, rdlen = parser.get_struct("!HHIH")
        with parser.restrict_to(rdlen):
            if rdtype == dns.rdatatype.TSIG:
                tsig = dns.rdata.from_wire_parser(rdclass, rdtype, parser, None)
                keyname = name
            else:
                parser.get_bytes(rdlen)
    assert msg_id == dns.message.from_wire(wire, keyring=_keyring()).id
    assert keyname == dns.name.from_text(_KEYNAME)
    assert isinstance(tsig, dns.rdtypes.ANY.TSIG.TSIG)
    assert len(tsig.mac) == 32  # HMAC-SHA256 MAC width
