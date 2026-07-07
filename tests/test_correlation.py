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

"""Correlation-id propagation tests (T-M6-03, SPEC §11.4).

Throwaway key material only (via the shared conftest fixtures).
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator

import dns.name
import dns.rcode
import dns.tsig
import dns.update
import httpx
import pytest
import pytest_asyncio
from tests.conftest import UpdateBuilder
from tests.test_api_app import make_settings

from astropath.api.app import create_app
from astropath.correlation import (
    CorrelationIdFilter,
    correlation_scope,
    get_correlation_id,
    new_api_correlation_id,
    new_dns_correlation_id,
)
from astropath.data_plane.protocol import handle_query
from astropath.logging_config import configure_logging
from astropath.observability import DataPlaneMetrics


def test_new_dns_correlation_id_embeds_request_id() -> None:
    assert new_dns_correlation_id(0x1A2B).startswith("dns-1a2b-")
    assert new_dns_correlation_id(0x1_0001).startswith("dns-0001-")  # masked to 16 bits


def test_new_api_correlation_id_shape() -> None:
    cid = new_api_correlation_id()
    assert cid.startswith("api-")
    assert len(cid) == len("api-") + 16


def test_correlation_scope_sets_and_restores() -> None:
    assert get_correlation_id() is None
    with correlation_scope("dns-aaaa-bbbb"):
        assert get_correlation_id() == "dns-aaaa-bbbb"
        with correlation_scope("dns-cccc-dddd"):
            assert get_correlation_id() == "dns-cccc-dddd"
        assert get_correlation_id() == "dns-aaaa-bbbb"  # inner restored
    assert get_correlation_id() is None  # outer restored


def test_filter_stamps_bound_id_and_dash_when_unset() -> None:
    flt = CorrelationIdFilter()
    record = logging.LogRecord("t", logging.INFO, __file__, 1, "m", None, None)
    flt.filter(record)
    assert record.correlation_id == "-"  # type: ignore[attr-defined]
    with correlation_scope("dns-1234-5678"):
        flt.filter(record)
    assert record.correlation_id == "dns-1234-5678"  # type: ignore[attr-defined]


# --------------------------------------------------------------------------- #
# DNS pipeline: handle_query binds an id derived from the DNS request id.
# --------------------------------------------------------------------------- #
class _RecordingDispatcher:
    """A fake dispatcher that captures the correlation id active during dispatch."""

    def __init__(self) -> None:
        self.seen: str | None = None

    async def dispatch(
        self, msg: dns.update.UpdateMessage, *, source: str
    ) -> dns.rcode.Rcode:
        self.seen = get_correlation_id()
        logging.getLogger("astropath.test.dispatch").info("dispatched")
        return dns.rcode.NOERROR


async def test_handle_query_binds_request_id_correlation(
    make_signed_update: UpdateBuilder,
    keyring: dict[dns.name.Name, dns.tsig.Key],
    metrics: DataPlaneMetrics,
) -> None:
    wire = make_signed_update()
    expected_id = int.from_bytes(wire[:2], "big")
    dispatcher = _RecordingDispatcher()

    reply = await handle_query(
        wire, keyring, dispatcher, source="203.0.113.7", metrics=metrics
    )

    assert reply is not None
    assert dispatcher.seen is not None
    assert dispatcher.seen.startswith(f"dns-{expected_id:04x}-")
    assert get_correlation_id() is None  # scope closed after handle_query returns


async def test_challenge_logs_carry_the_correlation_id(
    make_signed_update: UpdateBuilder,
    keyring: dict[dns.name.Name, dns.tsig.Key],
    metrics: DataPlaneMetrics,
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_logging(make_settings())
    dispatcher = _RecordingDispatcher()

    await handle_query(
        make_signed_update(), keyring, dispatcher, source="203.0.113.7", metrics=metrics
    )

    out = capsys.readouterr().out
    dispatch_lines = [ln for ln in out.splitlines() if "dispatched" in ln]
    assert dispatch_lines, "no dispatch log line captured"
    assert dispatcher.seen is not None
    assert f"[{dispatcher.seen}]" in dispatch_lines[0]  # id present in the log column


# --------------------------------------------------------------------------- #
# Management plane: middleware binds + echoes X-Correlation-ID.
# --------------------------------------------------------------------------- #
@pytest_asyncio.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=create_app(settings=make_settings()))
    async with httpx.AsyncClient(
        transport=transport, base_url="http://astropath.test"
    ) as c:
        yield c


async def test_response_carries_generated_correlation_id(
    client: httpx.AsyncClient,
) -> None:
    response = await client.get("/healthz")
    assert response.headers["x-correlation-id"].startswith("api-")


async def test_inbound_request_id_is_honored(client: httpx.AsyncClient) -> None:
    response = await client.get("/healthz", headers={"X-Request-ID": "trace-42.abc"})
    assert response.headers["x-correlation-id"] == "trace-42.abc"


async def test_inbound_correlation_header_is_sanitized(
    client: httpx.AsyncClient,
) -> None:
    # Unsafe characters (spaces, punctuation) are stripped — no log injection.
    response = await client.get(
        "/healthz", headers={"X-Correlation-ID": "bad value!<script>"}
    )
    assert response.headers["x-correlation-id"] == "badvaluescript"
