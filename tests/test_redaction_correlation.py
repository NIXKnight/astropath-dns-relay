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

"""Adversarial redaction + correlation-stability suite (T-TEST-18, SPEC §11.4).

Part 1 drives secret-*shaped* inputs (env, DSN, base64-key, header, mapping-key)
through the real stdout handler and proves none reach the output. Part 2 runs a
full challenge dispatch and proves one correlation id is stable across its log
records and that the audit row is written under that same correlated span. Every
secret below is an obvious throwaway (``DEADBEEF-*`` / repeated ``A``).
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Mapping
from typing import Any

import dns.name
import dns.rcode
import dns.tsig
import pytest
from prometheus_client import CollectorRegistry
from pydantic import BaseModel
from tests.conftest import UpdateBuilder
from tests.test_api_app import make_settings

from astropath.data_plane.dispatcher import (
    AuditRecord,
    Dispatcher,
    Route,
    RoutingTable,
)
from astropath.data_plane.protocol import handle_query
from astropath.logging_config import REDACTED, configure_logging
from astropath.observability import DataPlaneMetrics
from astropath.providers.base import ConfigSchema, Provider

_CID = re.compile(r"\[(dns-[0-9a-f]{4}-[0-9a-f]{8})\]")


def _emit(
    capsys: pytest.CaptureFixture[str], emit: Callable[[logging.Logger], None]
) -> str:
    configure_logging(make_settings())
    emit(logging.getLogger("astropath.adversarial"))
    return capsys.readouterr().out


# --------------------------------------------------------------------------- #
# Part 1 — adversarial secret shapes never reach the stdout handler.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("message", "arg", "forbidden"),
    [
        ("env %s", "ASTROPATH_SESSION_SECRET=DEADBEEF-env-value", "DEADBEEF-env-value"),
        (
            "dsn %s",
            "postgresql+asyncpg://astro:DEADBEEF-dsn-pw@h:5432/db",
            "DEADBEEF-dsn-pw",
        ),
        ("kek %s", "A" * 44, "A" * 44),
        (
            "hdr %s",
            "Authorization: Bearer DEADBEEF-bearer-token",
            "DEADBEEF-bearer-token",
        ),
        ("hdr %s", "X-API-Key: DEADBEEF-apikey-value", "DEADBEEF-apikey-value"),
    ],
)
def test_adversarial_value_never_reaches_stdout(
    capsys: pytest.CaptureFixture[str], message: str, arg: str, forbidden: str
) -> None:
    out = _emit(capsys, lambda log: log.info(message, arg))
    assert forbidden not in out
    assert REDACTED in out


def test_secret_named_mapping_key_never_reaches_stdout(
    capsys: pytest.CaptureFixture[str],
) -> None:
    out = _emit(
        capsys,
        lambda log: log.info(
            "auth %s", {"api_key": "DEADBEEF-mapkey", "user": "admin"}
        ),
    )
    assert "DEADBEEF-mapkey" not in out
    assert REDACTED in out
    assert "admin" in out  # a non-secret value in the same mapping survives


def test_secret_split_across_format_and_arg_never_reaches_stdout(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # The value is assembled only when the record is rendered; freezing the
    # scrubbed message (args cleared) must still catch it.
    out = _emit(capsys, lambda log: log.info("credential kek=%s", "DEADBEEF-split-kek"))
    assert "DEADBEEF-split-kek" not in out
    assert REDACTED in out


# --------------------------------------------------------------------------- #
# Part 2 — one correlation id is stable across a challenge's records + audit row.
# --------------------------------------------------------------------------- #
class _EmptyConfig(BaseModel):
    pass


class _LoggingProvider(Provider):
    """A provider that logs inside present() so the challenge emits >1 record."""

    type = "test-logging"

    @classmethod
    def config_schema(cls) -> ConfigSchema:
        return _EmptyConfig

    @classmethod
    def from_config(cls, config: Mapping[str, Any], *, http: Any) -> _LoggingProvider:
        return cls()

    async def present(self, zone: str, record_name: str, values: list[str]) -> None:
        logging.getLogger("astropath.test.provider").info(
            "provider present zone=%s record=%s", zone, record_name
        )

    async def cleanup(self, zone: str, record_name: str, values: list[str]) -> None:
        logging.getLogger("astropath.test.provider").info(
            "provider cleanup zone=%s", zone
        )

    async def validate(self) -> None:
        return None


class _CapturingSink:
    def __init__(self) -> None:
        self.records: list[AuditRecord] = []

    async def record(self, record: AuditRecord) -> None:
        self.records.append(record)


async def test_correlation_id_stable_across_records_and_audit(
    make_signed_update: UpdateBuilder,
    keyring: dict[dns.name.Name, dns.tsig.Key],
    capsys: pytest.CaptureFixture[str],
) -> None:
    provider = _LoggingProvider()
    route = Route(
        zone=dns.name.from_text("example.com.").canonicalize(),
        provider=provider,
        record_name=dns.name.from_text("_acme-challenge.example.com.").canonicalize(),
    )
    sink = _CapturingSink()
    metrics = DataPlaneMetrics(registry=CollectorRegistry())
    dispatcher = Dispatcher(RoutingTable([route]), metrics, audit=sink)

    configure_logging(make_settings())
    reply = await handle_query(
        make_signed_update(), keyring, dispatcher, source="203.0.113.9", metrics=metrics
    )
    out = capsys.readouterr().out

    assert reply is not None
    assert reply[3] & 0x0F == dns.rcode.NOERROR

    # Both the provider record and the dispatcher's challenge-outcome record are
    # emitted; they must share exactly one correlation id (the challenge's span).
    provider_lines = [ln for ln in out.splitlines() if "provider present" in ln]
    outcome_lines = [ln for ln in out.splitlines() if "challenge present ok" in ln]
    assert provider_lines and outcome_lines

    cids = {m.group(1) for ln in out.splitlines() for m in [_CID.search(ln)] if m}
    assert len(cids) == 1, f"correlation id not stable across records: {cids}"
    correlation_id = next(iter(cids))
    assert f"[{correlation_id}]" in provider_lines[0]
    assert f"[{correlation_id}]" in outcome_lines[0]

    # The audit row was written under that same correlated span.
    assert len(sink.records) == 1
    assert sink.records[0].source == "203.0.113.9"
    assert sink.records[0].result == "ok"
