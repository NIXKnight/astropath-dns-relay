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

"""Audit-write unit tests (T-M2-06, HIGH-8, SPEC §6.1).

The dispatcher writes exactly one append-only audit record per challenge and
isolates any sink failure from the DNS answer. A fake sink observes the records
without a database; :class:`DbAuditSink`'s field mapping is checked against a fake
session. Real Postgres persistence is exercised in T-TEST-12.
"""

from __future__ import annotations

from collections.abc import Callable
from types import TracebackType
from typing import cast

import dns.message
import dns.name
import dns.rcode
import dns.tsig
import dns.update
from prometheus_client import CollectorRegistry
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from tests._fakes import FakeProvider, routing_for

from astropath.audit import DbAuditSink
from astropath.data_plane.dispatcher import AuditRecord, Dispatcher, TsigKeyResolver
from astropath.models import ChallengeEvent
from astropath.observability import DataPlaneMetrics


class FakeSink:
    """Records AuditRecords in memory; raises when ``fail`` is set."""

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.records: list[AuditRecord] = []

    async def record(self, record: AuditRecord) -> None:
        if self.fail:
            raise RuntimeError("db down")
        self.records.append(record)


def _dispatcher(
    provider: FakeProvider,
    sink: FakeSink,
    *,
    resolver: TsigKeyResolver | None = None,
) -> tuple[Dispatcher, CollectorRegistry]:
    reg = CollectorRegistry()
    dispatcher = Dispatcher(
        routing_for(provider),
        DataPlaneMetrics(registry=reg),
        clock=lambda: 1000.0,
        audit=sink,
        tsig_key_resolver=resolver,
    )
    return dispatcher, reg


def _unsigned_update(
    *, delete: bool = False, value: str = "tok"
) -> dns.update.UpdateMessage:
    u = dns.update.UpdateMessage("example.com.")
    if delete:
        u.delete("_acme-challenge.example.com.", "TXT", value)
    else:
        u.add("_acme-challenge.example.com.", 300, "TXT", value)
    msg = dns.message.from_wire(u.to_wire())
    assert isinstance(msg, dns.update.UpdateMessage)
    return msg


async def test_present_writes_one_audit_record() -> None:
    provider = FakeProvider()
    sink = FakeSink()
    dispatcher, _reg = _dispatcher(provider, sink)

    rcode = await dispatcher.dispatch(_unsigned_update(value="tok"), source="1.2.3.4")

    assert rcode == dns.rcode.NOERROR
    assert len(sink.records) == 1
    row = sink.records[0]
    assert row.zone == "example.com."
    assert row.record_name == "_acme-challenge.example.com."
    assert row.action == "present"
    assert row.provider == "fake"
    assert row.result == "ok"
    assert row.latency_ms >= 0
    assert row.source == "1.2.3.4"
    assert row.tsig_key_id is None  # no resolver / unsigned
    assert row.error_detail is None


async def test_cleanup_writes_audit_record() -> None:
    provider = FakeProvider()
    sink = FakeSink()
    dispatcher, _reg = _dispatcher(provider, sink)

    await dispatcher.dispatch(_unsigned_update(delete=True), source="1.2.3.4")

    assert [r.action for r in sink.records] == ["cleanup"]


async def test_provider_error_audits_error_detail_and_servfails() -> None:
    provider = FakeProvider(fail=True)
    sink = FakeSink()
    dispatcher, _reg = _dispatcher(provider, sink)

    rcode = await dispatcher.dispatch(_unsigned_update(), source="1.2.3.4")

    assert rcode == dns.rcode.SERVFAIL
    assert len(sink.records) == 1
    row = sink.records[0]
    assert row.result == "error"
    assert row.error_detail == "present boom"


async def test_cleanup_provider_error_audits_error_but_answers_noerror() -> None:
    """Deadlock regression (HIGH-8 + SPEC §3.6): a failing cleanup is answered
    NOERROR so the ACME order is not wedged, yet the audit row still records the
    error verbatim for forensics (result=error + error_detail)."""
    provider = FakeProvider(fail=True)
    sink = FakeSink()
    dispatcher, _reg = _dispatcher(provider, sink)

    rcode = await dispatcher.dispatch(_unsigned_update(delete=True), source="1.2.3.4")

    assert rcode == dns.rcode.NOERROR
    assert len(sink.records) == 1
    row = sink.records[0]
    assert row.action == "cleanup"
    assert row.result == "error"
    assert row.error_detail == "cleanup boom"


async def test_no_audit_row_for_refused_write_surface() -> None:
    # A REFUSED (policy) rejection never reaches the provider, so no audit row.
    provider = FakeProvider()
    sink = FakeSink()
    dispatcher, _reg = _dispatcher(provider, sink)

    u = dns.update.UpdateMessage("example.com.")
    u.add("www.example.com.", 300, "TXT", "tok")  # wrong owner -> REFUSED
    msg = dns.message.from_wire(u.to_wire())
    assert isinstance(msg, dns.update.UpdateMessage)

    rcode = await dispatcher.dispatch(msg, source="1.2.3.4")
    assert rcode == dns.rcode.REFUSED
    assert sink.records == []


async def test_audit_stamps_tsig_key_id_from_resolver(
    keyring: dict[dns.name.Name, dns.tsig.Key],
    make_signed_update: Callable[..., bytes],
) -> None:
    wire = make_signed_update(value="tok")
    msg = dns.message.from_wire(wire, keyring=keyring)
    assert isinstance(msg, dns.update.UpdateMessage)
    assert msg.keyname is not None  # signed -> resolver can run

    provider = FakeProvider()
    sink = FakeSink()
    dispatcher, _reg = _dispatcher(provider, sink, resolver=lambda _name: 42)

    await dispatcher.dispatch(msg, source="9.9.9.9")

    assert sink.records[0].tsig_key_id == 42


async def test_audit_failure_does_not_break_the_answer_path() -> None:
    provider = FakeProvider()
    sink = FakeSink(fail=True)  # every audit write raises
    dispatcher, reg = _dispatcher(provider, sink)

    # The provider still ran and the DNS reply is unaffected.
    rcode = await dispatcher.dispatch(_unsigned_update(), source="1.2.3.4")
    assert rcode == dns.rcode.NOERROR
    assert provider.present_calls  # provider was called
    assert reg.get_sample_value("astropath_audit_failures_total") == 1.0


# --------------------------------------------------------------------------- #
# DbAuditSink field mapping (persistence exercised in T-TEST-12)
# --------------------------------------------------------------------------- #
class _FakeSession:
    def __init__(self) -> None:
        self.added: list[object] = []
        self.committed = False

    async def __aenter__(self) -> _FakeSession:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> bool:
        return False

    def add(self, obj: object) -> None:
        self.added.append(obj)

    async def commit(self) -> None:
        self.committed = True


async def test_db_audit_sink_maps_record_to_challenge_event() -> None:
    session = _FakeSession()
    maker = cast(async_sessionmaker[AsyncSession], lambda: session)
    sink = DbAuditSink(maker)

    await sink.record(
        AuditRecord(
            zone="example.com.",
            record_name="_acme-challenge.example.com.",
            action="present",
            provider="hurricane",
            result="ok",
            latency_ms=12,
            tsig_key_id=3,
            source="1.2.3.4",
            error_detail=None,
        )
    )

    assert session.committed is True
    assert len(session.added) == 1
    event = session.added[0]
    assert isinstance(event, ChallengeEvent)
    assert event.zone == "example.com."
    assert event.action == "present"
    assert event.provider == "hurricane"
    assert event.result == "ok"
    assert event.latency_ms == 12
    assert event.tsig_key_id == 3
    assert event.source == "1.2.3.4"


def test_challenge_event_has_no_secret_fields() -> None:
    # Defense in depth: the audit row model exposes no secret-bearing attribute.
    fields = set(ChallengeEvent.model_fields)
    assert not fields & {"secret_encrypted", "config_encrypted", "token_hash"}
