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
connect-retry transport. Uses ``httpx.MockTransport`` for the app-layer tests
and a single 127.0.0.1 loopback server for the real-transport case, so no
external network is touched.
"""

from __future__ import annotations

import asyncio

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

    asyncio.run(run())


# --------------------------------------------------------------------------- #
# T-TEST-07 gap-fill: the 500-no-raise, bounded-attempts and stop-on-4xx clauses
# are proven above. The cases below close the remaining clauses — the REAL
# transport not retrying a 503 (connect-only), 429 handling, and the backoff
# growth/cap that the noop-sleep tests above deliberately do not assert.
# --------------------------------------------------------------------------- #


async def test_transport_retries_do_not_cover_503() -> None:
    """AC 'transport retries connect-only': the real ``AsyncHTTPTransport`` from
    ``build_async_client(connect_retries=n)`` must NOT retry a 503 — a 503 is a
    completed response, not a ``ConnectError``. A 127.0.0.1 loopback server (no
    external network) counts exactly one request despite ``retries=5``.
    """
    request_count = 0

    async def handle(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        nonlocal request_count
        header = await reader.readuntil(b"\r\n\r\n")
        request_count += 1
        length = 0
        for line in header.decode("latin-1").split("\r\n"):
            if line.lower().startswith("content-length:"):
                length = int(line.split(":", 1)[1].strip())
        if length:
            await reader.readexactly(length)
        writer.write(
            b"HTTP/1.1 503 Service Unavailable\r\n"
            b"Content-Length: 3\r\nConnection: close\r\n\r\nerr"
        )
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    host, port = server.sockets[0].getsockname()[:2]
    async with server:
        client = build_async_client(connect_retries=5)
        try:
            response = await client.post(f"http://{host}:{port}/", data={"x": "1"})
        finally:
            await client.aclose()

    assert response.status_code == 503
    assert request_count == 1  # connect-only retries never re-issued the 503


async def test_app_retry_treats_429_as_retryable() -> None:
    """AC 'app-retry handles 5xx/429': a 429 is retried like a 5xx, then recovers."""
    transport, calls = _counting_transport([429, 200])
    async with httpx.AsyncClient(transport=transport) as client:
        response = await post_with_retry(
            client,
            "https://provider.invalid/update",
            data={},
            max_attempts=3,
            sleep=_noop_sleep,
        )
    assert response.status_code == 200
    assert len(calls) == 2  # 429 retried once, then 200


async def test_app_retry_backoff_grows_exponentially_within_jitter_bounds() -> None:
    """AC 'app-retry honors backoff': successive waits grow exponentially with a
    bounded full-jitter term. base=0.5 -> exponential floors 0.5, 1.0, 2.0 plus
    jitter in [0, base), so each wait lands in [floor, floor+base].
    """
    waits: list[float] = []

    async def record_sleep(seconds: float) -> None:
        waits.append(seconds)

    transport, calls = _counting_transport([503, 503, 503, 200])
    async with httpx.AsyncClient(transport=transport) as client:
        response = await post_with_retry(
            client,
            "https://provider.invalid/update",
            data={},
            max_attempts=4,
            base_backoff=0.5,
            max_backoff=100.0,  # cap high enough that growth here is unclamped
            sleep=record_sleep,
        )
    assert response.status_code == 200
    assert len(waits) == 3  # one wait before each of the three retries
    assert 0.5 <= waits[0] <= 1.0
    assert 1.0 <= waits[1] <= 1.5
    assert 2.0 <= waits[2] <= 2.5
    assert waits[2] >= 2 * waits[0]  # third exponential floor is 4x the first


async def test_app_retry_backoff_is_capped_at_max_backoff() -> None:
    """AC 'bounded backoff': the exponential term is clamped at ``max_backoff``
    (jitter adds at most ``base_backoff`` on top), so waits never run away."""
    waits: list[float] = []

    async def record_sleep(seconds: float) -> None:
        waits.append(seconds)

    transport, calls = _counting_transport([503, 503, 503, 200])
    async with httpx.AsyncClient(transport=transport) as client:
        await post_with_retry(
            client,
            "https://provider.invalid/update",
            data={},
            max_attempts=4,
            base_backoff=0.5,
            max_backoff=1.0,  # low cap forces clamping on the later attempts
            sleep=record_sleep,
        )
    # Unclamped floors would be 0.5, 1.0, 2.0; the cap holds them to <= 1.0,
    # and full jitter adds at most base_backoff (0.5).
    assert all(wait <= 1.0 + 0.5 for wait in waits)
    assert waits[2] <= 1.0 + 0.5  # third wait clamped, not the unclamped 2.0+
