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

"""Challenge dispatcher: zone → backend → provider (SPEC §3, §4, §5).

Resolves the target zone from the UPDATE ZONE section, enforces the
``_acme-challenge`` TXT write-surface allowlist (BLOCKER-2), validates and
normalizes the TXT value, serializes pushes per FQDN (HE single-value), and
calls ``provider.present`` / ``provider.cleanup``. A provider failure maps to
SERVFAIL; success maps to NOERROR (SPEC §3.6).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

import dns.name
import dns.rdataclass
import dns.rrset
import dns.update

from astropath.providers.base import Provider


class ZoneResolutionError(ValueError):
    """The UPDATE has no usable ZONE section."""


def zone_from_message(msg: dns.update.UpdateMessage) -> dns.name.Name:
    """Read the target zone from the parsed UPDATE ZONE section (SPEC §3.9).

    The zone is the owner of the single ZONE-section rrset, canonicalized
    (lower-case, absolute) — NOT re-derived from the challenge FQDN.
    """
    if not msg.zone:
        raise ZoneResolutionError("UPDATE message has no ZONE section")
    return msg.zone[0].name.canonicalize()


@dataclass(frozen=True)
class Route:
    """A configured zone → provider mapping (SPEC §6.1 Domain, in-memory)."""

    zone: dns.name.Name  # canonical
    provider: Provider
    record_name: dns.name.Name  # canonical _acme-challenge.<zone>. handle


class RoutingTable:
    """In-memory zone → :class:`Route` map with longest-suffix matching (§3.9)."""

    def __init__(self, routes: Iterable[Route]) -> None:
        self._by_zone: dict[dns.name.Name, Route] = {r.zone: r for r in routes}

    def match(self, zone: dns.name.Name) -> Route | None:
        """Return the longest configured zone that equals or is a parent of
        ``zone``; ``None`` when no configured zone covers it (→ REFUSED)."""
        candidate = zone
        while True:
            route = self._by_zone.get(candidate)
            if route is not None:
                return route
            try:
                candidate = candidate.parent()
            except dns.name.NoParent:
                return None


class Action(Enum):
    """Whether an update-section rrset publishes or clears a challenge value."""

    PRESENT = "present"
    CLEANUP = "cleanup"


def classify_action(rrset: dns.rrset.RRset) -> Action:
    """Classify an UPDATE-section rrset as present vs cleanup (SPEC §3.8).

    dnspython records the RFC2136 update class on ``rrset.deleting`` (proven in
    :mod:`tests.test_dnspython_asserts`): ``None`` for an add (class IN),
    ``NONE`` (254, delete a specific RR) or ``ANY`` (255, delete the rrset) for a
    cleanup. Branching on ``rdclass`` is wrong — it stays IN for the rdata.
    """
    if rrset.deleting is None:
        return Action.PRESENT
    if rrset.deleting in (dns.rdataclass.NONE, dns.rdataclass.ANY):
        return Action.CLEANUP
    raise ValueError(f"unexpected update class deleting={rrset.deleting!r}")
