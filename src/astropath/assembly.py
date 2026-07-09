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

"""Shared data-plane assembly: decrypted config → runtime objects (SPEC §6.4).

The data plane serves from an **in-memory** view of the routing state: a keyring
of ``dns.tsig.Key`` objects, a :class:`~astropath.data_plane.dispatcher.RoutingTable`,
and one provider instance per backend. :func:`build_data_plane` turns a decrypted
:class:`BootstrapConfig` into exactly those objects. The database is the sole
source of that config (:func:`astropath.cache.load_config_from_db` decrypts the
``TsigKey`` / ``Backend`` / ``Domain`` rows into a :class:`BootstrapConfig`, then
hands it here) — this module is the source-agnostic seam between "decrypted
config" and "live runtime".

Secret discipline: the config dataclasses carry already-decrypted secrets (HE
per-record keys, TSIG base64 secrets); they live in memory only and are never
logged. ``build_data_plane`` never touches ciphertext or the KEK.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import dns.name
import dns.tsig
import httpx

from astropath.data_plane.dispatcher import Route, RoutingTable
from astropath.data_plane.tsig import TsigKeySpec, build_keyring
from astropath.providers.base import Provider, get_provider
from astropath.providers.hurricane import HurricaneProvider

__all__ = [
    "BackendConfig",
    "BootstrapConfig",
    "DataPlaneRuntime",
    "ZoneConfig",
    "build_data_plane",
]

Keyring = dict[dns.name.Name, dns.tsig.Key]


@dataclass(frozen=True)
class ZoneConfig:
    """One zone → provider mapping with a decrypted per-record secret."""

    zone: str
    provider: str
    record_name: str
    he_dynamic_key: str | None = None  # decrypted; redact in any diagnostic
    #: Unique backend identity (DB ``Backend.name``). ``None`` groups providers by
    #: type instead — the fallback for a zone with no named backend.
    backend: str | None = None


@dataclass(frozen=True)
class BackendConfig:
    """One provider backend's decrypted shared config (secrets in memory only).

    ``name`` is the backend's unique identity (the DB ``Backend.name``); it keys
    provider construction so two backends of the **same** ``provider`` type (e.g.
    two Route53 hosted zones) get separate instances. ``config`` is the decrypted
    shared config handed to ``Provider.from_config`` — **empty** for Hurricane
    Electric, whose per-record keys live on the Domain (HIGH-7).
    """

    name: str
    provider: str
    config: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BootstrapConfig:
    """Decrypted routing config the data plane assembles from (secrets in memory).

    Produced by :func:`astropath.cache.load_config_from_db` from the persisted
    ``TsigKey`` / ``Backend`` / ``Domain`` rows and consumed by
    :func:`build_data_plane`. Listener bind/port are process config (Settings),
    not part of this structure.
    """

    tsig_keys: list[TsigKeySpec] = field(default_factory=list)
    zones: list[ZoneConfig] = field(default_factory=list)
    #: Per-backend shared config; a zone without a named backend falls back to
    #: grouping providers by type.
    backends: list[BackendConfig] = field(default_factory=list)
    listener_host: str = "0.0.0.0"
    listener_port: int = 53


@dataclass
class DataPlaneRuntime:
    """The live runtime objects the data plane serves from."""

    keyring: Keyring
    routing: RoutingTable
    providers: list[Provider]


def build_data_plane(
    config: BootstrapConfig, *, http_client: httpx.AsyncClient
) -> DataPlaneRuntime:
    """Build the keyring + routing + providers from a decrypted config (SPEC §6.4).

    One provider instance is created **per backend** (keyed by
    :attr:`ZoneConfig.backend`, falling back to the provider type for a zone with
    no named backend), constructed from that backend's decrypted shared config via
    ``Provider.from_config`` (T-M5-05). Registry lookup stays by ``Backend.type``.
    HE keeps an empty backend config — its per-record dynamic keys are injected per
    zone (domain-scoped, HIGH-7). The shared ``httpx`` client is handed to every
    provider; Route53 owns its own aiobotocore session and ignores it.
    """
    keyring = build_keyring(config.tsig_keys)
    backends_by_name = {backend.name: backend for backend in config.backends}
    providers: dict[str, Provider] = {}
    routes: list[Route] = []

    for zone_config in config.zones:
        key = zone_config.backend or zone_config.provider
        provider = providers.get(key)
        if provider is None:
            backend: BackendConfig | None = None
            if zone_config.backend is not None:
                backend = backends_by_name.get(zone_config.backend)
            provider_type = (
                backend.provider if backend is not None else zone_config.provider
            )
            provider_config: Mapping[str, Any] = (
                backend.config if backend is not None else {}
            )
            provider_cls = get_provider(provider_type)
            provider = provider_cls.from_config(provider_config, http=http_client)
            providers[key] = provider

        if isinstance(provider, HurricaneProvider) and zone_config.he_dynamic_key:
            provider.register_record_key(
                zone_config.record_name, zone_config.he_dynamic_key
            )

        routes.append(
            Route(
                zone=dns.name.from_text(zone_config.zone).canonicalize(),
                provider=provider,
                record_name=dns.name.from_text(zone_config.record_name).canonicalize(),
            )
        )

    return DataPlaneRuntime(
        keyring=keyring,
        routing=RoutingTable(routes),
        providers=list(providers.values()),
    )
