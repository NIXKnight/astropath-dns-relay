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

"""httpx client lifecycle + retry-boundary tests (T-M1-19, SPEC §5.6).

Folds the T-TEST-07 acceptance content: httpx returns 5xx as a ``Response``
(never raises), the app-level retry handles 5xx/429 with bounded attempts and
stops on 4xx, and the client is built with an explicit timeout and a
connect-retry transport. Uses ``httpx.MockTransport`` so no network is touched.
"""

from __future__ import annotations

import httpx
import pytest

from astropath.providers._http import (
    DEFAULT_TIMEOUT,
    build_async_client,
    post_with_retry,
)


async def _noop_sleep(_seconds: float) -> None:
    return None


def _counting_transport(statuses: list[int]) -> tuple[httpx.MockTransport, list[int]]:
    """A transport returning ``statuses`` in order, recording each request."""
    calls: list[int] = []
    sequence = iter(statuses)

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        try:
            code = next(sequence)
        except StopIteration:
            code = statuses[-1]
        body = "good" if code == 200 else "err"
        return httpx.Response(code, text=body)

    return httpx.MockTransport(handler), calls


def test_build_async_client_sets_explicit_timeout_and_transport() -> None:
    client = build_async_client(connect_retries=3)
    try:
        assert client.timeout == DEFAULT_TIMEOUT  # never the implicit 5s default
        assert isinstance(client._transport, httpx.AsyncHTTPTransport)
    finally:
        # not awaited here — no requests were made, so no pool to drain
        pass


async def test_httpx_returns_5xx_as_response_without_raising() -> None:
    transport, calls = _counting_transport([500])
    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.post("https://provider.invalid/update", data={})
    assert response.status_code == 500  # httpx did not raise on 5xx
    assert len(calls) == 1


async def test_app_retry_recovers_after_transient_503() -> None:
    transport, calls = _counting_transport([503, 503, 200])
    async with httpx.AsyncClient(transport=transport) as client:
        response = await post_with_retry(
            client,
            "https://provider.invalid/update",
            data={"x": "1"},
            max_attempts=3,
            sleep=_noop_sleep,
        )
    assert response.status_code == 200
    assert len(calls) == 3


async def test_app_retry_exhausts_and_returns_last_5xx() -> None:
    transport, calls = _counting_transport([500, 500, 500, 500])
    async with httpx.AsyncClient(transport=transport) as client:
        response = await post_with_retry(
            client,
            "https://provider.invalid/update",
            data={},
            max_attempts=3,
            sleep=_noop_sleep,
        )
    assert response.status_code == 500  # returned, not raised
    assert len(calls) == 3  # bounded to max_attempts


async def test_app_retry_stops_immediately_on_4xx() -> None:
    transport, calls = _counting_transport([400, 200])
    async with httpx.AsyncClient(transport=transport) as client:
        response = await post_with_retry(
            client,
            "https://provider.invalid/update",
            data={},
            max_attempts=3,
            sleep=_noop_sleep,
        )
    assert response.status_code == 400
    assert len(calls) == 1  # client errors are not retried


def test_post_with_retry_rejects_bad_max_attempts() -> None:
    client = build_async_client()

    async def run() -> None:
        with pytest.raises(ValueError):
            await post_with_retry(client, "https://x.invalid", data={}, max_attempts=0)

    import asyncio

    asyncio.run(run())
