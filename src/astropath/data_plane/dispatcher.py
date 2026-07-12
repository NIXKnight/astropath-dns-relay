# SPDX-License-Identifier: GPL-3.0-or-later
#
# astropath-dns-relay — self-hosted ACME DNS-01 solver gateway.
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
import logging
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.TXT
import dns.rrset
import dns.update

from astropath.observability import DataPlaneMetrics
from astropath.providers.base import Provider, ProviderError

log = logging.getLogger("astropath.dispatcher")

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


class RoutingSource(Protocol):
    """A zone → :class:`Route` resolver the dispatcher reads (§3.9, MED-2).

    Satisfied structurally by :class:`RoutingTable` (a static file-sourced map,
    M1) and by the DB-backed in-memory cache (``astropath.cache.RoutingCache``,
    M2), so the dispatcher serves from either without change. A DB-backed cache
    returns from its last-good snapshot during a Postgres blip.
    """

    def match(self, zone: dns.name.Name) -> Route | None: ...


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


@dataclass(frozen=True)
class AuditRecord:
    """One challenge outcome to be persisted as a ``ChallengeEvent`` (HIGH-8).

    A plain, ORM-free value the dispatcher builds and hands to an
    :class:`AuditSink`. Carries **no secret material** — only the zone, record
    handle, action, provider, result, latency, authorizing TSIG key id, source
    IP, and an already-redacted error detail (a provider error string).
    """

    zone: str
    record_name: str
    action: str
    provider: str
    result: str
    latency_ms: int
    tsig_key_id: int | None
    source: str
    error_detail: str | None


class AuditSink(Protocol):
    """Persists an :class:`AuditRecord` (implemented by the DB sink, T-M2-06).

    Kept structural so the data plane never imports the ORM. A failing
    ``record`` must not break the DNS answer path — the dispatcher guards the
    call and downgrades a failure to a log line plus a metric (HIGH-8).
    """

    async def record(self, record: AuditRecord) -> None: ...


#: Resolves a verified request's TSIG key name to its ``TsigKey`` row id.
TsigKeyResolver = Callable[[dns.name.Name], int | None]


class Dispatcher:
    """Route a verified UPDATE to its provider and return the reply rcode.

    Implements the :class:`~astropath.data_plane.protocol.ChallengeDispatcher`
    interface. TSIG verification and the auth gate already happened upstream;
    this stage owns zone routing, the write-surface allowlist, TXT validation,
    and the provider call (SPEC §3.6): REFUSED for unknown-zone / write-surface
    rejections, SERVFAIL for provider failure, NOERROR on success.

    When an :class:`AuditSink` is supplied (M2), every provider call also writes
    one append-only ``ChallengeEvent`` (HIGH-8). The audit write is isolated: a
    failure is logged and counted, never propagated into the DNS answer. The
    optional ``tsig_key_resolver`` stamps the authorizing key id on the audit row.
    """

    def __init__(
        self,
        routing: RoutingSource,
        metrics: DataPlaneMetrics,
        *,
        clock: Callable[[], float] = time.time,
        audit: AuditSink | None = None,
        tsig_key_resolver: TsigKeyResolver | None = None,
    ) -> None:
        self._routing = routing
        self._metrics = metrics
        self._clock = clock
        self._audit = audit
        self._tsig_resolver = tsig_key_resolver
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
        tsig_key_id = self._resolve_tsig_key_id(msg)
        # Serialize per FQDN so concurrent challenges to one record queue instead
        # of racing the provider's single-value write (SPEC §3.13, HIGH-9).
        async with self._lock_for(rrset.name.canonicalize().to_text()):
            return await self._invoke_provider(
                route,
                action,
                record_name,
                values,
                source=source,
                tsig_key_id=tsig_key_id,
            )

    def _resolve_tsig_key_id(self, msg: dns.update.UpdateMessage) -> int | None:
        """Resolve the authorizing TSIG key row id for the audit trail (HIGH-8)."""
        if self._tsig_resolver is None or msg.keyname is None:
            return None
        return self._tsig_resolver(msg.keyname)

    async def _invoke_provider(
        self,
        route: Route,
        action: Action,
        record_name: str,
        values: list[str],
        *,
        source: str,
        tsig_key_id: int | None,
    ) -> dns.rcode.Rcode:
        provider = route.provider
        zone_text = route.zone.to_text()
        error_detail: str | None = None
        started = time.perf_counter()
        try:
            if action is Action.PRESENT:
                await provider.present(zone_text, record_name, values)
            else:
                await provider.cleanup(zone_text, record_name, values)
        except ProviderError as exc:
            result = "error"
            error_detail = str(exc)  # provider errors are already secret-free
            # ACME cleanup is best-effort (SPEC §3.6, §5.3): once a challenge is
            # validated a leftover TXT is harmless, and SERVFAIL on cleanup would
            # wedge the order — cert-manager allows one challenge per DNS name, so a
            # perpetually failing cleanup deadlocks every future issuance/renewal for
            # that name. Answer NOERROR for a cleanup failure (still audited and
            # counted below); present stays strict SERVFAIL, where a failed write
            # means the token never landed and the challenge must not be solved.
            rcode = (
                dns.rcode.NOERROR if action is Action.CLEANUP else dns.rcode.SERVFAIL
            )
        else:
            result, rcode = "ok", dns.rcode.NOERROR
        latency = time.perf_counter() - started
        # A suppressed cleanup failure (answered NOERROR) gets a dedicated
        # result="suppressed" series on the existing challenges counter — never a
        # hard "error", since the DNS answer succeeded; the audit row below still
        # records result="error" + the detail for forensics.
        cleanup_suppressed = result == "error" and action is Action.CLEANUP

        self._metrics.provider_call_duration.labels(provider=provider.type).observe(
            latency
        )
        self._metrics.record_challenge(
            provider.type,
            action.value,
            "suppressed" if cleanup_suppressed else result,
        )
        if result == "ok":
            self._metrics.mark_zone_success(zone_text, self._clock())

        # Correlated challenge-outcome line (SPEC §11.4): the correlation id set by
        # handle_query stamps this record, tying it to the challenge's other logs
        # and its ChallengeEvent audit row. Proves provider success/failure — the
        # HE good/nochg vs badauth outcome maps to result=ok/error (SPEC §16, LOW-4).
        # A suppressed cleanup failure logs at WARNING (answered NOERROR; §5.3).
        log.log(
            logging.WARNING if cleanup_suppressed else logging.INFO,
            "challenge %s %s zone=%s provider=%s latency_ms=%d source=%s",
            action.value,
            result,
            zone_text,
            provider.type,
            int(latency * 1000),
            source,
        )

        await self._write_audit(
            AuditRecord(
                zone=zone_text,
                record_name=record_name,
                action=action.value,
                provider=provider.type,
                result=result,
                latency_ms=int(latency * 1000),
                tsig_key_id=tsig_key_id,
                source=source,
                error_detail=error_detail,
            )
        )
        return rcode

    async def _write_audit(self, record: AuditRecord) -> None:
        """Persist the audit row, isolating any failure from the answer (HIGH-8).

        An append-only ``ChallengeEvent`` is written per challenge. If the sink
        fails (e.g. Postgres unreachable) the DNS reply is unaffected: the failure
        is logged and counted, never raised.
        """
        if self._audit is None:
            return
        try:
            await self._audit.record(record)
        except Exception:
            log.exception("audit_write_failed", extra={"zone": record.zone})
            self._metrics.record_audit_failure()
