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

"""Acceptance: challenge dispatcher (T-TEST-05).

HIGH-3. The zone is read from the UPDATE ZONE section (canonicalized, not
re-derived from the FQDN); the RFC2136 update class selects present vs cleanup
(IN -> present, NONE/ANY -> cleanup); a provider failure maps to SERVFAIL; and
pushes to one record serialize while distinct records run concurrently. Class
branch and zone read run through the assembled verified-wire pipeline; the
serialization guarantee is exercised with concurrent dispatches.
"""

from __future__ import annotations

import asyncio
import struct

import dns.message
import dns.name
import dns.rcode
import dns.tsig
import dns.update
import pytest
from prometheus_client import CollectorRegistry
from tests._fakes import FakeProvider, SlowProvider, route_for, routing_for

from astropath.data_plane.dispatcher import Dispatcher, RoutingTable
from astropath.data_plane.protocol import handle_query
from astropath.observability import DataPlaneMetrics

Keyring = dict[dns.name.Name, dns.tsig.Key]


def _rcode_of(wire: bytes) -> int:
    (flags,) = struct.unpack("!H", wire[2:4])
    return int(flags) & 0xF


def _signed(
    keyring: Keyring,
    *,
    zone: str = "example.com.",
    record: str = "_acme-challenge.example.com.",
    value: str = "tok",
    delete: bool = False,
    delete_rrset: bool = False,
) -> bytes:
    update = dns.update.UpdateMessage(
        zone,
        keyname=dns.name.from_text("cm-key."),
        keyring=keyring,
        keyalgorithm=dns.tsig.HMAC_SHA256,
    )
    if delete_rrset:
        update.delete(record, "TXT")
    elif delete:
        update.delete(record, "TXT", value)
    else:
        update.add(record, 300, "TXT", value)
    return update.to_wire()


async def _pipeline(
    wire: bytes, keyring: Keyring, provider: FakeProvider, *, zone: str = "example.com."
) -> int:
    metrics = DataPlaneMetrics(registry=CollectorRegistry())
    dispatcher = Dispatcher(routing_for(provider, zone), metrics)
    reply = await handle_query(
        wire, keyring, dispatcher, source="1.2.3.4", metrics=metrics
    )
    assert reply is not None
    return _rcode_of(reply)


async def test_zone_is_read_from_zone_section_canonically(keyring: Keyring) -> None:
    # The ZONE owner is upper-cased; routing must canonicalize and still match.
    provider = FakeProvider()
    rcode = await _pipeline(_signed(keyring, zone="EXAMPLE.COM."), keyring, provider)

    assert rcode == dns.rcode.NOERROR
    assert len(provider.present_calls) == 1
    zone_text, record_text, values = provider.present_calls[0]
    assert zone_text == "example.com."  # canonical zone resolved from the ZONE section
    assert record_text.lower() == "_acme-challenge.example.com."
    assert values == ("tok",)


async def test_unmanaged_zone_is_refused(keyring: Keyring) -> None:
    provider = FakeProvider()
    wire = _signed(keyring, zone="other.org.", record="_acme-challenge.other.org.")
    rcode = await _pipeline(wire, keyring, provider)

    assert rcode == dns.rcode.REFUSED  # zone not in the routing table
    assert provider.calls == []


async def test_add_class_in_routes_to_present(keyring: Keyring) -> None:
    provider = FakeProvider()
    rcode = await _pipeline(_signed(keyring), keyring, provider)

    assert rcode == dns.rcode.NOERROR
    assert len(provider.present_calls) == 1
    assert provider.cleanup_calls == []


@pytest.mark.parametrize(
    ("delete", "delete_rrset"),
    [
        pytest.param(True, False, id="class-none-delete-rr"),
        pytest.param(False, True, id="class-any-delete-rrset"),
    ],
)
async def test_delete_classes_route_to_cleanup(
    keyring: Keyring, delete: bool, delete_rrset: bool
) -> None:
    provider = FakeProvider()
    wire = _signed(keyring, delete=delete, delete_rrset=delete_rrset)
    rcode = await _pipeline(wire, keyring, provider)

    assert rcode == dns.rcode.NOERROR
    assert len(provider.cleanup_calls) == 1
    assert provider.present_calls == []


async def test_provider_error_maps_to_servfail(keyring: Keyring) -> None:
    provider = FakeProvider(fail=True)
    rcode = await _pipeline(_signed(keyring), keyring, provider)

    assert rcode == dns.rcode.SERVFAIL  # provider failure, not REFUSED


def _parsed(zone: str, record: str, value: str) -> dns.update.UpdateMessage:
    update = dns.update.UpdateMessage(zone)
    update.add(record, 300, "TXT", value)
    msg = dns.message.from_wire(update.to_wire())
    assert isinstance(msg, dns.update.UpdateMessage)
    return msg


async def test_pushes_to_one_record_are_serialized() -> None:
    provider = SlowProvider()
    dispatcher = Dispatcher(
        routing_for(provider), DataPlaneMetrics(registry=CollectorRegistry())
    )
    record = "_acme-challenge.example.com."
    await asyncio.gather(
        dispatcher.dispatch(_parsed("example.com.", record, "a"), source="x"),
        dispatcher.dispatch(_parsed("example.com.", record, "b"), source="y"),
    )
    assert provider.max_active == 1  # the single-value record never overlapped


async def test_distinct_records_run_concurrently() -> None:
    provider = SlowProvider()
    routing = RoutingTable(
        [route_for(provider, "a.com."), route_for(provider, "b.com.")]
    )
    dispatcher = Dispatcher(routing, DataPlaneMetrics(registry=CollectorRegistry()))
    await asyncio.gather(
        dispatcher.dispatch(
            _parsed("a.com.", "_acme-challenge.a.com.", "x"), source="x"
        ),
        dispatcher.dispatch(
            _parsed("b.com.", "_acme-challenge.b.com.", "y"), source="y"
        ),
    )
    assert provider.max_active == 2  # different FQDNs are not serialized
