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

"""Per-plane supervisor tests (T-M1-23, SPEC §2.1, HIGH-1)."""

from __future__ import annotations

import asyncio

from prometheus_client import CollectorRegistry

from astropath.observability import DataPlaneMetrics
from astropath.supervisor import RestartLimiter, supervise


async def _noop_sleep(_seconds: float) -> None:
    return None


def test_restart_limiter_allows_up_to_max_then_denies() -> None:
    now = [0.0]
    limiter = RestartLimiter(max_restarts=2, window_seconds=10.0, clock=lambda: now[0])
    assert limiter.allow() is True
    assert limiter.allow() is True
    assert limiter.allow() is False  # budget spent
    now[0] = 11.0  # window slides past the recorded events
    assert limiter.allow() is True


def test_restart_limiter_backoff_grows() -> None:
    limiter = RestartLimiter(base_backoff=1.0, max_backoff=100.0)
    limiter.allow()
    first = limiter.backoff()
    limiter.allow()
    second = limiter.backoff()
    assert 1.0 <= first < 2.0  # base + jitter
    assert second >= 2.0  # grows with restart count


async def test_crash_in_one_plane_does_not_stop_the_other() -> None:
    shutdown = asyncio.Event()
    metrics = DataPlaneMetrics(registry=CollectorRegistry())
    healthy_completed = asyncio.Event()

    async def healthy() -> None:
        await asyncio.sleep(0)
        healthy_completed.set()  # runs cleanly to completion

    crash_count = 0

    async def crashing() -> None:
        nonlocal crash_count
        crash_count += 1
        raise RuntimeError("boom")

    await asyncio.gather(
        supervise(
            "healthy", healthy, shutdown, RestartLimiter(), metrics, sleep=_noop_sleep
        ),
        supervise(
            "crash",
            crashing,
            shutdown,
            RestartLimiter(max_restarts=3, window_seconds=60.0),
            metrics,
            sleep=_noop_sleep,
        ),
    )

    assert healthy_completed.is_set()  # unaffected by the sibling's crashes
    assert crash_count == 4  # 3 permitted restarts + the final denied attempt


async def test_restart_budget_exhaustion_flags_unhealthy_and_shuts_down() -> None:
    shutdown = asyncio.Event()
    reg = CollectorRegistry()
    metrics = DataPlaneMetrics(registry=reg)

    async def always_crash() -> None:
        raise RuntimeError("boom")

    await supervise(
        "dns",
        always_crash,
        shutdown,
        RestartLimiter(max_restarts=2, window_seconds=60.0),
        metrics,
        sleep=_noop_sleep,
    )

    assert shutdown.is_set()
    assert reg.get_sample_value("astropath_plane_unhealthy", {"plane": "dns"}) == 1.0
    assert (
        reg.get_sample_value("astropath_plane_restarts_total", {"plane": "dns"}) == 3.0
    )


async def test_supervise_stops_on_shutdown_without_restart() -> None:
    shutdown = asyncio.Event()
    shutdown.set()
    metrics = DataPlaneMetrics(registry=CollectorRegistry())
    called = False

    async def factory() -> None:
        nonlocal called
        called = True

    await supervise("dns", factory, shutdown, RestartLimiter(), metrics)
    assert called is False  # shutdown already set -> never started
