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

"""Routing-cache unit tests (T-M2-05, SPEC §6.4, MED-2).

The cache lifecycle is tested with an injected loader (no database): the snapshot
swaps atomically on refresh, a failed refresh keeps the last-good snapshot, and a
dispatcher reading through the cache keeps serving across a simulated Postgres
blip. The DB-sourced loader (:func:`make_db_loader` /
:func:`load_config_from_db`) is exercised against real Postgres in T-TEST-12.
"""

from __future__ import annotations

import dns.message
import dns.name
import dns.rcode
import dns.update
import pytest
from prometheus_client import CollectorRegistry
from tests._fakes import FakeProvider, routing_for

from astropath.bootstrap import DataPlaneRuntime
from astropath.cache import CacheSnapshot, RoutingCache
from astropath.data_plane.dispatcher import Dispatcher
from astropath.observability import DataPlaneMetrics

_TSIG_NAME = dns.name.from_text("cm-key.")


class _StatefulLoader:
    """A switchable loader: returns a snapshot until ``fail`` is set."""

    def __init__(self, snapshot: CacheSnapshot) -> None:
        self.snapshot = snapshot
        self.fail = False
        self.calls = 0

    async def __call__(self) -> CacheSnapshot:
        self.calls += 1
        if self.fail:
            raise RuntimeError("db down")
        return self.snapshot


def _snapshot(provider: FakeProvider, *, zone: str = "example.com.") -> CacheSnapshot:
    runtime = DataPlaneRuntime(
        keyring={}, routing=routing_for(provider, zone), providers=[provider]
    )
    return CacheSnapshot(runtime=runtime, tsig_key_ids={_TSIG_NAME.canonicalize(): 7})


def _parsed_update(
    *, zone: str = "example.com.", value: str = "tok"
) -> dns.update.UpdateMessage:
    u = dns.update.UpdateMessage(zone)
    u.add(f"_acme-challenge.{zone}", 300, "TXT", value)
    msg = dns.message.from_wire(u.to_wire())
    assert isinstance(msg, dns.update.UpdateMessage)
    return msg


def test_empty_cache_is_unpopulated() -> None:
    cache = RoutingCache(_StatefulLoader(_snapshot(FakeProvider())))
    assert cache.is_populated is False
    assert cache.snapshot is None
    assert cache.match(dns.name.from_text("example.com.")) is None
    assert cache.keyring == {}
    assert cache.providers == []
    assert cache.tsig_key_id_for(_TSIG_NAME) is None


async def test_refresh_populates_and_routes() -> None:
    provider = FakeProvider()
    cache = RoutingCache(_StatefulLoader(_snapshot(provider)))
    await cache.refresh()

    assert cache.is_populated is True
    route = cache.match(dns.name.from_text("example.com."))
    assert route is not None
    assert route.provider is provider
    assert cache.providers == [provider]
    assert cache.tsig_key_id_for(_TSIG_NAME) == 7


async def test_tsig_id_lookup_is_canonical() -> None:
    cache = RoutingCache(_StatefulLoader(_snapshot(FakeProvider())))
    await cache.refresh()
    # Mixed-case / trailing-dot variants resolve to the same id.
    assert cache.tsig_key_id_for(dns.name.from_text("CM-KEY.")) == 7
    assert cache.tsig_key_id_for(dns.name.from_text("unknown.")) is None


async def test_failed_refresh_keeps_last_good_snapshot() -> None:
    provider = FakeProvider()
    loader = _StatefulLoader(_snapshot(provider))
    cache = RoutingCache(loader)
    await cache.refresh()  # good load

    loader.fail = True
    with pytest.raises(RuntimeError):
        await cache.refresh()  # DB blip

    # The previous snapshot is retained — the write-path still resolves.
    assert cache.is_populated is True
    assert cache.match(dns.name.from_text("example.com.")) is not None


async def test_dispatch_reads_cache_and_survives_db_blip() -> None:
    provider = FakeProvider()
    loader = _StatefulLoader(_snapshot(provider))
    cache = RoutingCache(loader)
    await cache.refresh()

    metrics = DataPlaneMetrics(registry=CollectorRegistry())
    dispatcher = Dispatcher(cache, metrics)

    rcode = await dispatcher.dispatch(_parsed_update(value="tok"), source="1.2.3.4")
    assert rcode == dns.rcode.NOERROR
    assert provider.present_calls == [
        ("example.com.", "_acme-challenge.example.com.", ("tok",))
    ]

    # Postgres goes away mid-renewal: refresh fails, snapshot stays, dispatch OK.
    loader.fail = True
    with pytest.raises(RuntimeError):
        await cache.refresh()

    rcode2 = await dispatcher.dispatch(_parsed_update(value="tok2"), source="1.2.3.4")
    assert rcode2 == dns.rcode.NOERROR
    assert len(provider.present_calls) == 2
