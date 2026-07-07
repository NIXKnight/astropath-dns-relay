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

"""Independent per-plane supervision (SPEC §2.1, HIGH-1).

Each plane runs under its own :func:`supervise` loop — deliberately **not**
``asyncio.gather`` (which orphans the healthy sibling on a crash) and **not** a
top-level ``TaskGroup`` (which cancels the healthy sibling). A crash in one plane
is caught, metered, and restarted with exponential backoff; the sibling plane is
untouched. When a plane exhausts its restart budget the supervisor flags it
unhealthy and sets the shared shutdown event so ``main()`` can exit non-zero and
let the container orchestrator restart the whole process cleanly.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from collections import deque
from collections.abc import Awaitable, Callable

from astropath.observability import DataPlaneMetrics

__all__ = ["RestartLimiter", "supervise"]

log = logging.getLogger("astropath.supervisor")

PlaneFactory = Callable[[], Awaitable[None]]
Sleeper = Callable[[float], Awaitable[None]]


class RestartLimiter:
    """Sliding-window restart-rate limit with exponential backoff (SPEC §2.1)."""

    def __init__(
        self,
        max_restarts: int = 5,
        window_seconds: float = 60.0,
        *,
        base_backoff: float = 0.5,
        max_backoff: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._max = max_restarts
        self._window = window_seconds
        self._base_backoff = base_backoff
        self._max_backoff = max_backoff
        self._clock = clock
        self._events: deque[float] = deque()

    def allow(self) -> bool:
        """Record a restart attempt; return ``False`` once the budget is spent."""
        now = self._clock()
        cutoff = now - self._window
        while self._events and self._events[0] <= cutoff:
            self._events.popleft()
        if len(self._events) >= self._max:
            return False
        self._events.append(now)
        return True

    def backoff(self) -> float:
        """Exponential backoff (by recent restart count) plus full jitter."""
        count = max(len(self._events), 1)
        delay = min(self._max_backoff, self._base_backoff * (2.0 ** (count - 1)))
        return delay + random.uniform(0.0, self._base_backoff)


async def supervise(
    name: str,
    factory: PlaneFactory,
    shutdown: asyncio.Event,
    limiter: RestartLimiter,
    metrics: DataPlaneMetrics,
    *,
    sleep: Sleeper = asyncio.sleep,
) -> None:
    """Run ``factory`` under restart supervision until it completes or gives up.

    Returns when the plane finishes cleanly or its restart budget is exhausted;
    re-raises ``CancelledError`` for coordinated shutdown.
    """
    while not shutdown.is_set():
        try:
            await factory()
        except asyncio.CancelledError:
            raise  # shutdown path — propagate
        except Exception:
            log.exception("plane_crashed", extra={"plane": name})
            metrics.record_plane_restart(name)
            if not limiter.allow():
                metrics.set_plane_unhealthy(name, True)
                log.error("plane_restart_budget_exhausted", extra={"plane": name})
                shutdown.set()  # surface unhealthy; stop the process cleanly
                return
            await sleep(limiter.backoff())
            continue
        return  # factory returned normally — the plane is done
