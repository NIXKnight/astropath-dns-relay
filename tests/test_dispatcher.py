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

"""Dispatcher unit tests (T-M1-08.., SPEC §3, §4, §5)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import dns.message
import dns.name
import dns.update
import pytest
from pydantic import BaseModel

from astropath.data_plane.dispatcher import (
    Action,
    Route,
    RoutingTable,
    WriteSurfaceViolation,
    classify_action,
    validate_write_surface,
    zone_from_message,
)
from astropath.providers.base import Provider, ProviderError


class _FakeBase(Provider):
    """Provider base with the ``type`` attribute left annotation-only."""

    @classmethod
    def config_schema(cls) -> type[BaseModel]:
        return BaseModel

    @classmethod
    def from_config(cls, config: Mapping[str, Any], *, http: Any) -> Provider:
        return cls()

    async def validate(self) -> None:
        return None


class FakeProvider(_FakeBase):
    """Records present/cleanup calls; optionally raises ProviderError."""

    type = "fake"

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.present_calls: list[tuple[str, str, tuple[str, ...]]] = []
        self.cleanup_calls: list[tuple[str, str, tuple[str, ...]]] = []

    async def present(self, zone: str, record_name: str, values: list[str]) -> None:
        if self.fail:
            raise ProviderError("present boom")
        self.present_calls.append((zone, record_name, tuple(values)))

    async def cleanup(self, zone: str, record_name: str, values: list[str]) -> None:
        if self.fail:
            raise ProviderError("cleanup boom")
        self.cleanup_calls.append((zone, record_name, tuple(values)))


def _route(provider: Provider, zone: str = "example.com.") -> Route:
    return Route(
        zone=dns.name.from_text(zone).canonicalize(),
        provider=provider,
        record_name=dns.name.from_text(f"_acme-challenge.{zone}").canonicalize(),
    )


def _parsed_update(
    *,
    delete: bool = False,
    delete_rrset: bool = False,
    zone: str = "example.com.",
    record: str | None = None,
    value: str = "tok",
    rdtype: str = "TXT",
) -> dns.update.UpdateMessage:
    owner = record if record is not None else f"_acme-challenge.{zone}"
    u = dns.update.UpdateMessage(zone)
    if delete_rrset:
        u.delete(owner, rdtype)
    elif delete:
        u.delete(owner, rdtype, value)
    else:
        u.add(owner, 300, rdtype, value)
    msg = dns.message.from_wire(u.to_wire())
    assert isinstance(msg, dns.update.UpdateMessage)
    return msg


def test_classify_add_is_present() -> None:
    rrset = _parsed_update().update[0]
    assert classify_action(rrset) is Action.PRESENT


def test_classify_delete_specific_rr_is_cleanup() -> None:
    """Class-NONE delete (cert-manager cleanup) routes to CLEANUP."""
    rrset = _parsed_update(delete=True).update[0]
    assert classify_action(rrset) is Action.CLEANUP


def test_classify_delete_entire_rrset_is_cleanup() -> None:
    """Class-ANY delete routes to CLEANUP."""
    rrset = _parsed_update(delete_rrset=True).update[0]
    assert classify_action(rrset) is Action.CLEANUP


# --------------------------------------------------------------------------- #
# T-M1-09: zone from ZONE section + longest-match routing
# --------------------------------------------------------------------------- #
def test_zone_from_message_reads_zone_section() -> None:
    msg = _parsed_update(zone="Example.COM.")
    assert zone_from_message(msg) == dns.name.from_text("example.com.")  # canonical


def test_routing_exact_match() -> None:
    provider = FakeProvider()
    table = RoutingTable([_route(provider, "example.com.")])
    route = table.match(dns.name.from_text("example.com."))
    assert route is not None
    assert route.provider is provider


def test_routing_longest_suffix_match() -> None:
    table = RoutingTable(
        [
            _route(FakeProvider(), "example.com."),
            _route(FakeProvider(), "sub.example.com."),
        ]
    )
    matched = table.match(dns.name.from_text("sub.example.com."))
    assert matched is not None
    assert matched.zone == dns.name.from_text("sub.example.com.")


def test_routing_unknown_zone_returns_none() -> None:
    table = RoutingTable([_route(FakeProvider(), "example.com.")])
    assert table.match(dns.name.from_text("other.org.")) is None


# --------------------------------------------------------------------------- #
# T-M1-15: write-surface allowlist (BLOCKER-2)
# --------------------------------------------------------------------------- #
def _mixed_update() -> dns.update.UpdateMessage:
    u = dns.update.UpdateMessage("example.com.")
    u.add("_acme-challenge.example.com.", 300, "TXT", "tok")
    u.add("www.example.com.", 300, "A", "192.0.2.1")  # extra rrset -> reject whole
    msg = dns.message.from_wire(u.to_wire())
    assert isinstance(msg, dns.update.UpdateMessage)
    return msg


def test_write_surface_accepts_acme_challenge_txt_add() -> None:
    route = _route(FakeProvider())
    action, rrset = validate_write_surface(_parsed_update(), route)
    assert action is Action.PRESENT
    assert rrset.name == dns.name.from_text("_acme-challenge.example.com.")


def test_write_surface_accepts_acme_challenge_txt_delete() -> None:
    route = _route(FakeProvider())
    action, _ = validate_write_surface(_parsed_update(delete=True), route)
    assert action is Action.CLEANUP


def test_write_surface_rejects_wrong_owner() -> None:
    route = _route(FakeProvider())
    msg = _parsed_update(record="www.example.com.")  # TXT but not _acme-challenge
    with pytest.raises(WriteSurfaceViolation):
        validate_write_surface(msg, route)


def test_write_surface_rejects_non_txt_type() -> None:
    route = _route(FakeProvider())
    msg = _parsed_update(
        record="_acme-challenge.example.com.", rdtype="A", value="192.0.2.1"
    )
    with pytest.raises(WriteSurfaceViolation):
        validate_write_surface(msg, route)


def test_write_surface_rejects_mixed_rrsets() -> None:
    route = _route(FakeProvider())
    with pytest.raises(WriteSurfaceViolation):
        validate_write_surface(_mixed_update(), route)
