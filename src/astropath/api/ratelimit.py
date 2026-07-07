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

"""In-process login rate limiting and lockout (SPEC §8.5, HIGH-5).

A single-process sliding-window limiter guards ``POST /auth/login``: after
``max_attempts`` failures within ``window`` seconds a source IP is locked out with
**exponential** backoff (each further failed burst doubles the delay, capped). A
coarser **global** window caps a distributed guessing attack across many IPs. On a
successful login the source's failure history is cleared.

Deterministic clock injection makes the decay testable without sleeping. No
password or credential material is ever stored here — only source keys and
failure timestamps.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable

__all__ = ["LoginRateLimiter"]


class LoginRateLimiter:
    """Sliding-window per-source + global login limiter with exponential lockout."""

    def __init__(
        self,
        *,
        max_attempts: int = 5,
        window_seconds: float = 300.0,
        base_lockout: float = 60.0,
        max_lockout: float = 3600.0,
        global_max_attempts: int = 20,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._max = max_attempts
        self._window = window_seconds
        self._base = base_lockout
        self._max_lockout = max_lockout
        self._global_max = global_max_attempts
        self._clock = clock
        self._failures: dict[str, deque[float]] = {}
        self._locked_until: dict[str, float] = {}
        self._global: deque[float] = deque()
        self._global_locked_until = 0.0

    def _prune(self, events: deque[float], now: float) -> None:
        cutoff = now - self._window
        while events and events[0] <= cutoff:
            events.popleft()

    def is_allowed(self, key: str) -> bool:
        """Whether ``key`` may attempt a login now (not currently locked out)."""
        now = self._clock()
        if now < self._global_locked_until:
            return False
        return now >= self._locked_until.get(key, 0.0)

    def record_failure(self, key: str) -> None:
        """Record a failed attempt for ``key`` and (re)compute any lockout."""
        now = self._clock()
        events = self._failures.setdefault(key, deque())
        events.append(now)
        self._prune(events, now)
        self._global.append(now)
        self._prune(self._global, now)

        if len(events) >= self._max:
            # Exponential backoff by how far the burst exceeds the threshold.
            over = len(events) - self._max
            delay = min(self._max_lockout, self._base * (2.0**over))
            self._locked_until[key] = now + delay
        if len(self._global) >= self._global_max:
            self._global_locked_until = now + self._base

    def record_success(self, key: str) -> None:
        """Clear the failure history + lockout for ``key`` after a good login."""
        self._failures.pop(key, None)
        self._locked_until.pop(key, None)

    def retry_after(self, key: str) -> int:
        """Seconds until ``key`` may retry (for a ``Retry-After`` header)."""
        now = self._clock()
        until = max(self._locked_until.get(key, 0.0), self._global_locked_until)
        return max(0, int(until - now))
