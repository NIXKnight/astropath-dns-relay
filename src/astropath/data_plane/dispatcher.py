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

import asyncio
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import Enum

import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.TXT
import dns.rrset
import dns.update

from astropath.observability import DataPlaneMetrics
from astropath.providers.base import Provider, ProviderError

# ACME DNS-01 tokens are a 43-char base64url SHA-256 digest; a TXT
# character-string is bounded to 255 octets on the wire regardless.
_MAX_TXT_LEN = 255


class ZoneResolutionError(ValueError):
    """The UPDATE has no usable ZONE section."""


class WriteSurfaceViolation(Exception):
    """The UPDATE violates the ``_acme-challenge`` TXT allowlist (→ REFUSED).

    A valid TSIG is NOT a general zone-write credential (BLOCKER-2); anything
    outside the allowlist is rejected before any provider dispatch.
    """


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


def validate_write_surface(
    msg: dns.update.UpdateMessage, route: Route
) -> tuple[Action, dns.rrset.RRset]:
    """Enforce the write-surface allowlist (SPEC §4.1, BLOCKER-2).

    Accept ONLY an ADD/DELETE of a single TXT rrset owned by exactly
    ``_acme-challenge.<zone>``. Any other owner/type/class, or an UPDATE mixing
    in any other rrset, is rejected whole with :class:`WriteSurfaceViolation`
    (the caller maps that to REFUSED). The (empty) prerequisite section is
    ignored — cert-manager may send none (SPEC §3.10).
    """
    if len(msg.update) != 1:
        raise WriteSurfaceViolation(
            f"UPDATE section must contain exactly one rrset, got {len(msg.update)}"
        )
    rrset = msg.update[0]
    if rrset.rdtype != dns.rdatatype.TXT:
        raise WriteSurfaceViolation(
            f"only TXT rrsets are permitted, got {dns.rdatatype.to_text(rrset.rdtype)}"
        )
    if rrset.name.canonicalize() != route.record_name:
        raise WriteSurfaceViolation(
            f"owner {rrset.name} is not the permitted _acme-challenge record"
        )
    try:
        action = classify_action(rrset)
    except ValueError as exc:
        raise WriteSurfaceViolation(str(exc)) from exc
    return action, rrset


def normalize_txt_values(
    rrset: dns.rrset.RRset, action: Action, *, allow_multivalue: bool = False
) -> list[str]:
    """Validate and normalize the TXT rdata to raw token strings (SPEC §4.2).

    Strips DNS TXT wire/string quoting (dnspython stores TXT as one or more
    character-strings) to the raw token the provider expects. Enforces: exactly
    one value for single-value providers, non-empty, ``<= 255`` chars. A
    class-ANY cleanup (delete the whole rrset) legitimately carries no value and
    yields an empty list.
    """
    rdatas = list(rrset)
    if not rdatas:
        if action is Action.CLEANUP:
            return []  # delete-entire-rrset: no value carried
        raise WriteSurfaceViolation("present requires a TXT value")
    if len(rdatas) > 1 and not allow_multivalue:
        raise WriteSurfaceViolation(
            f"multiple TXT values not permitted for a single-value provider "
            f"(got {len(rdatas)})"
        )

    values: list[str] = []
    for rdata in rdatas:
        if not isinstance(rdata, dns.rdtypes.ANY.TXT.TXT):
            raise WriteSurfaceViolation("rrset rdata is not TXT")
        raw = b"".join(rdata.strings)  # normalize quoting -> raw token bytes
        try:
            token = raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise WriteSurfaceViolation("TXT value is not ASCII") from exc
        if not token:
            raise WriteSurfaceViolation("empty TXT value")
        if len(token) > _MAX_TXT_LEN:
            raise WriteSurfaceViolation(f"TXT value exceeds {_MAX_TXT_LEN} characters")
        values.append(token)
    return values


class Dispatcher:
    """Route a verified UPDATE to its provider and return the reply rcode.

    Implements the :class:`~astropath.data_plane.protocol.ChallengeDispatcher`
    interface. TSIG verification and the auth gate already happened upstream;
    this stage owns zone routing, the write-surface allowlist, TXT validation,
    and the provider call (SPEC §3.6): REFUSED for unknown-zone / write-surface
    rejections, SERVFAIL for provider failure, NOERROR on success.
    """

    def __init__(
        self,
        routing: RoutingTable,
        metrics: DataPlaneMetrics,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._routing = routing
        self._metrics = metrics
        self._clock = clock
        # One lock per record owner (SPEC §3.13): HE holds a single value per
        # dynamic record, so overlapping pushes to one FQDN must not clobber.
        self._locks: dict[str, asyncio.Lock] = {}

    def _lock_for(self, record_key: str) -> asyncio.Lock:
        lock = self._locks.get(record_key)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[record_key] = lock
        return lock

    async def dispatch(
        self, msg: dns.update.UpdateMessage, *, source: str
    ) -> dns.rcode.Rcode:
        try:
            zone = zone_from_message(msg)
        except ZoneResolutionError:
            return dns.rcode.REFUSED
        route = self._routing.match(zone)
        if route is None:
            return dns.rcode.REFUSED  # zone not managed here

        try:
            action, rrset = validate_write_surface(msg, route)
            values = normalize_txt_values(
                rrset, action, allow_multivalue=route.provider.supports_multivalue
            )
        except WriteSurfaceViolation:
            return dns.rcode.REFUSED

        record_name = rrset.name.to_text()
        # Serialize per FQDN so concurrent challenges to one record queue instead
        # of racing the provider's single-value write (SPEC §3.13, HIGH-9).
        async with self._lock_for(rrset.name.canonicalize().to_text()):
            return await self._invoke_provider(route, action, record_name, values)

    async def _invoke_provider(
        self,
        route: Route,
        action: Action,
        record_name: str,
        values: list[str],
    ) -> dns.rcode.Rcode:
        provider = route.provider
        zone_text = route.zone.to_text()
        started = time.perf_counter()
        try:
            if action is Action.PRESENT:
                await provider.present(zone_text, record_name, values)
            else:
                await provider.cleanup(zone_text, record_name, values)
        except ProviderError:
            self._metrics.record_challenge(provider.type, action.value, "error")
            return dns.rcode.SERVFAIL
        finally:
            self._metrics.provider_call_duration.labels(provider=provider.type).observe(
                time.perf_counter() - started
            )
        self._metrics.record_challenge(provider.type, action.value, "ok")
        self._metrics.mark_zone_success(zone_text, self._clock())
        return dns.rcode.NOERROR
