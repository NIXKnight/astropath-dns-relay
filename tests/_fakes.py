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

"""Reusable test doubles for the M1 acceptance suites (T-TEST-02/04/05).

A recording :class:`FakeProvider` (optionally failing) and a concurrency-probing
:class:`SlowProvider` stand in for a real DNS backend so the acceptance tests can
observe exactly which provider calls a verified UPDATE produces — without any
network. Not a test module (leading underscore keeps pytest from collecting it).
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any

import dns.name
from pydantic import BaseModel

from astropath.data_plane.dispatcher import Route, RoutingTable
from astropath.providers.base import Provider, ProviderError

ProviderCall = tuple[str, str, tuple[str, ...]]


class _FakeBase(Provider):
    """Provider base with the abstract plumbing filled in (``type`` per subclass)."""

    @classmethod
    def config_schema(cls) -> type[BaseModel]:
        return BaseModel

    @classmethod
    def from_config(cls, config: Mapping[str, Any], *, http: Any) -> Provider:
        return cls()

    async def validate(self) -> None:
        return None


class FakeProvider(_FakeBase):
    """Records present/cleanup calls; raises ProviderError when ``fail`` is set."""

    type = "fake"

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.present_calls: list[ProviderCall] = []
        self.cleanup_calls: list[ProviderCall] = []

    async def present(self, zone: str, record_name: str, values: list[str]) -> None:
        if self.fail:
            raise ProviderError("present boom")
        self.present_calls.append((zone, record_name, tuple(values)))

    async def cleanup(self, zone: str, record_name: str, values: list[str]) -> None:
        if self.fail:
            raise ProviderError("cleanup boom")
        self.cleanup_calls.append((zone, record_name, tuple(values)))

    @property
    def calls(self) -> list[ProviderCall]:
        """All provider calls, present and cleanup, in the order recorded."""
        return self.present_calls + self.cleanup_calls


class SlowProvider(_FakeBase):
    """Tracks peak in-flight concurrency to prove per-FQDN serialization."""

    type = "slow"

    def __init__(self) -> None:
        self.active = 0
        self.max_active = 0

    async def _work(self) -> None:
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        await asyncio.sleep(0)  # yield so a racing task can interleave
        await asyncio.sleep(0)
        self.active -= 1

    async def present(self, zone: str, record_name: str, values: list[str]) -> None:
        await self._work()

    async def cleanup(self, zone: str, record_name: str, values: list[str]) -> None:
        await self._work()


def route_for(provider: Provider, zone: str = "example.com.") -> Route:
    """A zone→provider route with the canonical ``_acme-challenge.<zone>`` owner."""
    return Route(
        zone=dns.name.from_text(zone).canonicalize(),
        provider=provider,
        record_name=dns.name.from_text(f"_acme-challenge.{zone}").canonicalize(),
    )


def routing_for(provider: Provider, zone: str = "example.com.") -> RoutingTable:
    """A single-zone :class:`RoutingTable` pointing at ``provider``."""
    return RoutingTable([route_for(provider, zone)])
