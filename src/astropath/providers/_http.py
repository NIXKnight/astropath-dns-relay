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

"""Shared httpx client lifecycle + two-layer retry (SPEC §5.6, HIGH-9/HIGH-11).

One long-lived :class:`httpx.AsyncClient` is created per provider backend by
``main()`` and closed on shutdown (connection pooling). Two retry layers are kept
strictly separate:

1. **Connection-level** — :class:`httpx.AsyncHTTPTransport` ``retries=`` retries
   *only* ``ConnectError`` / ``ConnectTimeout`` (SPEC §5.6 ``[C7]``). It does NOT
   retry read/write timeouts and does NOT retry HTTP status codes.
2. **Status-level** — :func:`post_with_retry`, a bounded app-level retry with
   exponential backoff + jitter around 5xx/429. httpx does **not** raise on
   4xx/5xx by default, so the status is inspected explicitly (SPEC §5.6).

The implicit 5s default timeout is never used; an explicit
:class:`httpx.Timeout` is always set.
"""

from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable, Mapping

import httpx

__all__ = [
    "DEFAULT_TIMEOUT",
    "RETRYABLE_STATUS",
    "build_async_client",
    "post_with_retry",
]

# Explicit, bounded timeout for every provider call (never the implicit 5s).
DEFAULT_TIMEOUT = httpx.Timeout(10.0, connect=5.0, read=10.0, write=10.0, pool=10.0)

# Status codes worth an app-level retry (transient server / rate-limit).
RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})


def build_async_client(
    *,
    timeout: httpx.Timeout = DEFAULT_TIMEOUT,
    connect_retries: int = 2,
) -> httpx.AsyncClient:
    """Build a pooled ``AsyncClient`` with connect-only transport retries.

    ``connect_retries`` is passed to :class:`httpx.AsyncHTTPTransport`, which
    retries **only** connection establishment failures — never a 5xx and never a
    read/write timeout (SPEC §5.6). Status retries are handled by
    :func:`post_with_retry`.
    """
    transport = httpx.AsyncHTTPTransport(retries=connect_retries)
    return httpx.AsyncClient(timeout=timeout, transport=transport)


async def post_with_retry(
    client: httpx.AsyncClient,
    url: str,
    *,
    data: Mapping[str, str],
    max_attempts: int = 3,
    base_backoff: float = 0.5,
    max_backoff: float = 8.0,
    retry_status: frozenset[int] = RETRYABLE_STATUS,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> httpx.Response:
    """POST form data with bounded status-level retry (SPEC §5.6).

    Returns the final :class:`httpx.Response` even when it is an error status —
    httpx does not raise on 4xx/5xx, and neither does this function; the caller
    inspects ``status_code``. Only ``retry_status`` codes are retried; any other
    status (2xx/3xx/4xx) returns immediately. Connection errors are already
    retried at the transport layer and propagate if still failing.
    """
    if max_attempts < 1:
        raise ValueError("max_attempts must be >= 1")

    attempt = 0
    while True:
        attempt += 1
        response = await client.post(url, data=data)
        if response.status_code not in retry_status or attempt >= max_attempts:
            return response
        backoff = min(max_backoff, base_backoff * (2 ** (attempt - 1)))
        backoff += random.uniform(0.0, base_backoff)  # full jitter component
        await sleep(backoff)
