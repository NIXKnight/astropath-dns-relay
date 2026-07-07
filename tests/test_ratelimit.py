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

"""Login rate-limit / lockout (T-M3-07, SPEC §8.5, HIGH-5).

Unit tests use a deterministic clock to prove: lockout after ``max_attempts``,
decay after the lockout window, per-source isolation, success reset, and the
global cap. An in-process integration test drives ``POST /auth/login`` through the
real app: failures lock the source (429) and a decayed clock lets a correct login
back in. No credential material is stored by the limiter.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest_asyncio
from tests._api import api_client, login
from tests.test_api_app import make_settings

from astropath.api.app import create_app
from astropath.api.ratelimit import LoginRateLimiter


class _Clock:
    """A hand-advanced monotonic clock."""

    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


# --------------------------------------------------------------------------- #
# Unit
# --------------------------------------------------------------------------- #
def test_locks_out_after_max_attempts() -> None:
    clock = _Clock()
    limiter = LoginRateLimiter(max_attempts=3, base_lockout=60.0, clock=clock)
    assert limiter.is_allowed("ip") is True
    for _ in range(3):
        limiter.record_failure("ip")
    assert limiter.is_allowed("ip") is False
    assert limiter.retry_after("ip") == 60


def test_lockout_decays_after_window() -> None:
    clock = _Clock()
    limiter = LoginRateLimiter(max_attempts=3, base_lockout=60.0, clock=clock)
    for _ in range(3):
        limiter.record_failure("ip")
    assert limiter.is_allowed("ip") is False
    clock.t = 61.0  # past the lockout
    assert limiter.is_allowed("ip") is True


def test_lockout_is_exponential() -> None:
    clock = _Clock()
    limiter = LoginRateLimiter(max_attempts=3, base_lockout=60.0, clock=clock)
    for _ in range(3):  # threshold -> 60s
        limiter.record_failure("ip")
    assert limiter.retry_after("ip") == 60
    limiter.record_failure("ip")  # one over -> 120s
    assert limiter.retry_after("ip") == 120
    limiter.record_failure("ip")  # two over -> 240s
    assert limiter.retry_after("ip") == 240


def test_per_source_isolation() -> None:
    clock = _Clock()
    limiter = LoginRateLimiter(max_attempts=3, clock=clock)
    for _ in range(3):
        limiter.record_failure("attacker")
    assert limiter.is_allowed("attacker") is False
    assert limiter.is_allowed("innocent") is True


def test_success_resets_failures() -> None:
    clock = _Clock()
    limiter = LoginRateLimiter(max_attempts=3, clock=clock)
    limiter.record_failure("ip")
    limiter.record_failure("ip")
    limiter.record_success("ip")
    limiter.record_failure("ip")
    assert limiter.is_allowed("ip") is True  # counter restarted


def test_global_cap_locks_all_sources() -> None:
    clock = _Clock()
    limiter = LoginRateLimiter(
        max_attempts=100, global_max_attempts=5, base_lockout=60.0, clock=clock
    )
    for i in range(5):  # distinct sources, under per-source threshold
        limiter.record_failure(f"ip-{i}")
    # The global window tripped: a brand-new source is refused too.
    assert limiter.is_allowed("fresh-ip") is False


# --------------------------------------------------------------------------- #
# Integration through the app
# --------------------------------------------------------------------------- #
class _FailingAuth:
    async def verify_admin_password(self, password: str) -> bool:
        return password == "correct-pw"

    async def api_token_valid(self, api_key: str) -> bool:
        return False


@pytest_asyncio.fixture
async def client_and_clock() -> AsyncIterator[tuple[httpx.AsyncClient, _Clock]]:
    app = create_app(settings=make_settings())
    clock = _Clock()
    app.state.astropath.auth = _FailingAuth()
    app.state.astropath.rate_limiter = LoginRateLimiter(
        max_attempts=3, base_lockout=60.0, clock=clock
    )
    async with api_client(app) as c:
        yield c, clock


async def test_login_lockout_then_decay(
    client_and_clock: tuple[httpx.AsyncClient, _Clock],
) -> None:
    client, clock = client_and_clock
    for _ in range(3):
        assert (await login(client, "wrong")).status_code == 401
    # Fourth attempt is locked out regardless of the password.
    locked = await login(client, "correct-pw")
    assert locked.status_code == 429
    assert "Retry-After" in locked.headers

    clock.t = 61.0  # lockout window elapsed
    assert (await login(client, "correct-pw")).status_code == 200
