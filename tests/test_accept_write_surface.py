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

"""Acceptance: write-surface allowlist + ACME TXT validation (T-TEST-04).

BLOCKER-2 + MED-9, driven through the assembled pipeline (verified wire ->
handle_query -> real Dispatcher -> provider). A valid TSIG is proven to be *not*
a general zone-write credential: only an ADD/DELETE of a single TXT rrset owned
by exactly ``_acme-challenge.<zone>`` with one in-bounds value passes; every
other owner, type, mixed message, or malformed value is REFUSED and the provider
is never called.
"""

from __future__ import annotations

import struct
from collections.abc import Callable

import dns.name
import dns.rcode
import dns.tsig
import dns.update
import pytest
from prometheus_client import CollectorRegistry
from tests._fakes import FakeProvider, routing_for

from astropath.data_plane.dispatcher import Dispatcher
from astropath.data_plane.protocol import handle_query
from astropath.observability import DataPlaneMetrics

Keyring = dict[dns.name.Name, dns.tsig.Key]
Builder = Callable[[dns.update.UpdateMessage], None]

_RECORD = "_acme-challenge.example.com."
# One TXT rdata carrying two char-strings that join past the 255-octet bound.
_OVERSIZED = '"' + "a" * 255 + '" "' + "b" * 255 + '"'


def _new(keyring: Keyring) -> dns.update.UpdateMessage:
    """A TSIG-capable UPDATE addressed at example.com. (signs on to_wire)."""
    return dns.update.UpdateMessage(
        "example.com.",
        keyname=dns.name.from_text("cm-key."),
        keyring=keyring,
        keyalgorithm=dns.tsig.HMAC_SHA256,
    )


def _rcode_of(wire: bytes) -> int:
    (flags,) = struct.unpack("!H", wire[2:4])
    return int(flags) & 0xF


async def _run(wire: bytes, keyring: Keyring) -> tuple[int, FakeProvider]:
    provider = FakeProvider()
    metrics = DataPlaneMetrics(registry=CollectorRegistry())
    dispatcher = Dispatcher(routing_for(provider), metrics)
    reply = await handle_query(
        wire, keyring, dispatcher, source="1.2.3.4", metrics=metrics
    )
    assert reply is not None  # a signed reply is always produced for a signed UPDATE
    return _rcode_of(reply), provider


# --- reject builders: each mutates the UPDATE into a surface violation --------
def _b_wrong_owner(u: dns.update.UpdateMessage) -> None:
    u.add("www.example.com.", 300, "TXT", "tok")  # TXT but not _acme-challenge


def _b_non_txt(u: dns.update.UpdateMessage) -> None:
    u.add(_RECORD, 300, "A", "192.0.2.1")  # right owner, wrong type


def _b_mixed_rrsets(u: dns.update.UpdateMessage) -> None:
    u.add(_RECORD, 300, "TXT", "tok")
    u.add("www.example.com.", 300, "A", "192.0.2.1")  # a valid TXT smuggling an A


def _b_multi_value(u: dns.update.UpdateMessage) -> None:
    u.add(_RECORD, 300, "TXT", "v1", "v2")  # two values, single-value provider


def _b_oversized(u: dns.update.UpdateMessage) -> None:
    u.add(_RECORD, 300, "TXT", _OVERSIZED)  # joins past 255 octets


def _b_empty(u: dns.update.UpdateMessage) -> None:
    u.add(_RECORD, 300, "TXT", '""')  # present with an empty value


@pytest.mark.parametrize(
    "builder",
    [
        pytest.param(_b_wrong_owner, id="wrong-owner"),
        pytest.param(_b_non_txt, id="non-txt-type"),
        pytest.param(_b_mixed_rrsets, id="mixed-rrsets"),
        pytest.param(_b_multi_value, id="multi-value"),
        pytest.param(_b_oversized, id="oversized-value"),
        pytest.param(_b_empty, id="empty-value"),
    ],
)
async def test_surface_violation_is_refused_and_provider_untouched(
    keyring: Keyring, builder: Builder
) -> None:
    update = _new(keyring)
    builder(update)
    rcode, provider = await _run(update.to_wire(), keyring)

    assert rcode == dns.rcode.REFUSED  # rejected despite a valid signature
    assert provider.calls == []  # TSIG is not a zone-write credential (BLOCKER-2)


async def test_valid_acme_challenge_add_passes(keyring: Keyring) -> None:
    update = _new(keyring)
    update.add(_RECORD, 300, "TXT", "valid-token-123")
    rcode, provider = await _run(update.to_wire(), keyring)

    assert rcode == dns.rcode.NOERROR
    assert provider.present_calls == [
        ("example.com.", _RECORD, ("valid-token-123",))  # raw token, quoting stripped
    ]


async def test_valid_acme_challenge_delete_passes(keyring: Keyring) -> None:
    update = _new(keyring)
    update.delete(_RECORD, "TXT", "valid-token-123")
    rcode, provider = await _run(update.to_wire(), keyring)

    assert rcode == dns.rcode.NOERROR
    assert provider.cleanup_calls == [("example.com.", _RECORD, ("valid-token-123",))]


async def test_quoted_token_is_normalized_to_raw(keyring: Keyring) -> None:
    update = _new(keyring)
    update.add(_RECORD, 300, "TXT", '"quoted-token"')  # DNS char-string quoting
    rcode, provider = await _run(update.to_wire(), keyring)

    assert rcode == dns.rcode.NOERROR
    assert provider.present_calls == [("example.com.", _RECORD, ("quoted-token",))]
