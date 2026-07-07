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

"""argon2 semantics + event-loop offload (T-TEST-11, SPEC §7.4, HIGH-5/HIGH-11).

Proves: argon2 ``verify`` **raises** ``VerifyMismatchError`` (never returns
``False``); the store wraps that into a bool; ``check_needs_rehash`` drives a
re-hash to current params; the login verify is offloaded via ``asyncio.to_thread``
so the CPU-bound hash does not block the event loop (loop-latency evidence). A
micro-benchmark records the per-verify wall time. Throwaway credential only.
"""

from __future__ import annotations

import asyncio
import time

import pytest
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from pydantic import SecretStr
from tests.test_api_app import make_settings

from astropath.api.auth import AuthService
from astropath.store import (
    hash_password,
    password_needs_rehash,
    verify_password,
)

_PASSWORD = "throwaway-argon2-subject"


def test_argon2_verify_raises_not_returns_false() -> None:
    # The raw argon2 primitive raises on a wrong password (never a bool).
    hasher = PasswordHasher()
    stored = hasher.hash(_PASSWORD)
    assert hasher.verify(stored, _PASSWORD) is True
    with pytest.raises(VerifyMismatchError):
        hasher.verify(stored, "wrong-password")


def test_store_verify_password_wraps_mismatch_into_bool() -> None:
    stored = hash_password(_PASSWORD)
    assert verify_password(stored, _PASSWORD) is True
    assert verify_password(stored, "wrong-password") is False  # no exception leaks


def test_check_needs_rehash_drives_reencode_to_current_params() -> None:
    # A hash made with weaker-than-default params must be flagged for re-hash;
    # the re-hashed value then matches current params.
    weak = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
    outdated = weak.hash(_PASSWORD)
    assert password_needs_rehash(outdated) is True

    upgraded = hash_password(_PASSWORD)
    assert password_needs_rehash(upgraded) is False
    assert verify_password(upgraded, _PASSWORD) is True


async def test_login_verify_is_offloaded_and_does_not_block_loop() -> None:
    # AuthService.verify_admin_password uses asyncio.to_thread; while it runs, the
    # event loop must stay responsive. A ticker coroutine advances only if the
    # loop is not blocked by the CPU-bound argon2 verify.
    settings = make_settings(admin_password_hash=SecretStr(hash_password(_PASSWORD)))
    auth = AuthService(None, settings)

    ticks = 0
    stop = asyncio.Event()

    async def ticker() -> None:
        nonlocal ticks
        while not stop.is_set():
            ticks += 1
            await asyncio.sleep(0.001)

    ticker_task = asyncio.create_task(ticker())
    try:
        assert await auth.verify_admin_password(_PASSWORD) is True
    finally:
        stop.set()
        await ticker_task

    # If verify ran inline the loop would be frozen for the whole hash; the ticker
    # advancing proves the offload kept the loop live.
    assert ticks > 1


def test_per_verify_latency_micro_benchmark() -> None:
    # [ASSERT] the verify does real work (>1ms) — a trivial/no-op hash would be a
    # security regression. Recorded for the hardware-tuning note (SPEC §7.4).
    stored = hash_password(_PASSWORD)
    start = time.perf_counter()
    verify_password(stored, _PASSWORD)
    elapsed = time.perf_counter() - start
    assert elapsed > 0.001, f"argon2 verify implausibly fast: {elapsed * 1000:.3f} ms"
    print(f"\nargon2 per-verify latency: {elapsed * 1000:.2f} ms")
