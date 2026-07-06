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

"""In-memory routing cache sourced from the database (T-M2-05, SPEC §6.4, MED-2).

The DNS write-path reads an **in-memory snapshot**, never the database, so a brief
Postgres outage during a renewal cannot fail a challenge. The snapshot is loaded
at startup and refreshed on management-API writes (event/callback, not a
per-challenge poll — T-M3-16 wires the hooks).

Runtime reuse (SPEC §16.3): the database rows are decrypted into the same
:class:`~astropath.bootstrap.BootstrapConfig` the M1 file loader produces, then
handed to the **shared** :func:`~astropath.bootstrap.build_data_plane` — identical
runtime objects (keyring of ``Key`` objects, :class:`RoutingTable`, provider
instances), only the source differs (file → DB).

Degraded behavior (SPEC §6.4): :meth:`RoutingCache.refresh` swaps the snapshot
only on success. A failed refresh (DB unreachable) propagates to the caller for
logging/metrics but leaves the last-good snapshot in place, so the data plane
keeps serving. If the cache is still empty (startup with an unreachable DB), DNS
readiness stays false (§11.2) but the process does not crash.

Secret discipline: HE per-record keys and TSIG secrets are decrypted into memory
only (via :class:`~astropath.store.SecretCodec`) and never logged.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import dns.name
import dns.tsig
import httpx
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlmodel import select

from astropath.bootstrap import (
    BootstrapConfig,
    DataPlaneRuntime,
    ZoneConfig,
    build_data_plane,
)
from astropath.crypto import Kek
from astropath.data_plane.dispatcher import Route
from astropath.data_plane.tsig import TsigKeySpec
from astropath.models import Backend, Domain, TsigKey
from astropath.providers.base import Provider
from astropath.store import SecretCodec

__all__ = [
    "CacheSnapshot",
    "RoutingCache",
    "SnapshotLoader",
    "load_config_from_db",
    "load_tsig_key_ids",
    "make_db_loader",
]

Keyring = dict[dns.name.Name, dns.tsig.Key]

#: An async callable that builds a fresh :class:`CacheSnapshot` from its source.
SnapshotLoader = Callable[[], Awaitable["CacheSnapshot"]]


async def load_config_from_db(session: AsyncSession, kek: Kek) -> BootstrapConfig:
    """Decrypt the persisted rows into a :class:`BootstrapConfig` (SPEC §16.3).

    Mirrors :func:`astropath.bootstrap.load_bootstrap` but reads the database:
    every ``TsigKey`` becomes a :class:`TsigKeySpec` and every ``Domain`` (joined
    to its ``Backend`` for the provider type) becomes a :class:`ZoneConfig` with
    the HE per-record key decrypted in memory. Listener bind/port are process
    config (Settings), not DB rows, so the defaults are left untouched.
    """
    codec = SecretCodec(kek)

    tsig_rows = (await session.execute(select(TsigKey))).scalars().all()
    tsig_keys = [
        TsigKeySpec(
            name=row.name,
            algorithm=row.algorithm,
            secret_b64=codec.decrypt_text(row.secret_encrypted),
        )
        for row in tsig_rows
    ]

    backend_rows = (await session.execute(select(Backend))).scalars().all()
    backend_type_by_id = {row.id: row.type for row in backend_rows}

    domain_rows = (await session.execute(select(Domain))).scalars().all()
    zones = [
        ZoneConfig(
            zone=row.zone,
            provider=backend_type_by_id[row.backend_id],
            record_name=row.record_name,
            he_dynamic_key=(
                codec.decrypt_text(row.secret_encrypted)
                if row.secret_encrypted is not None
                else None
            ),
        )
        for row in domain_rows
    ]

    return BootstrapConfig(tsig_keys=tsig_keys, zones=zones)


async def load_tsig_key_ids(session: AsyncSession) -> dict[dns.name.Name, int]:
    """Map each TSIG key's canonical DNS name to its row id (for audit rows).

    Used by the DB-backed dispatcher (T-M2-06) to stamp ``ChallengeEvent`` rows
    with the authorizing ``tsig_key_id``. Names are canonicalized so the lookup
    matches the parsed request key name regardless of case/trailing dot.
    """
    rows = (await session.execute(select(TsigKey.id, TsigKey.name))).all()
    ids: dict[dns.name.Name, int] = {}
    for key_id, name in rows:
        if key_id is not None:
            ids[dns.name.from_text(name).canonicalize()] = key_id
    return ids


@dataclass(frozen=True)
class CacheSnapshot:
    """An atomically-swappable view of the routing state (SPEC §6.4).

    Holds the built :class:`DataPlaneRuntime` (keyring, routing, providers) plus
    the canonical TSIG name → id map for audit stamping.
    """

    runtime: DataPlaneRuntime
    tsig_key_ids: dict[dns.name.Name, int]


def make_db_loader(
    sessionmaker: async_sessionmaker[AsyncSession],
    kek: Kek,
    http_client: httpx.AsyncClient,
) -> SnapshotLoader:
    """Build a :data:`SnapshotLoader` that reads the database (SPEC §16.3).

    Decrypts the rows into a :class:`BootstrapConfig`, feeds the **shared**
    :func:`build_data_plane`, and captures the TSIG id map — the whole DB→runtime
    path in one injectable callable, so :class:`RoutingCache` stays source-
    agnostic and unit-testable.
    """

    async def _load() -> CacheSnapshot:
        async with sessionmaker() as session:
            config = await load_config_from_db(session, kek)
            tsig_ids = await load_tsig_key_ids(session)
        runtime = build_data_plane(config, http_client=http_client)
        return CacheSnapshot(runtime=runtime, tsig_key_ids=tsig_ids)

    return _load


class RoutingCache:
    """The in-memory routing cache (SPEC §6.4, MED-2).

    Source-agnostic: it is constructed with a :data:`SnapshotLoader`
    (:func:`make_db_loader` for the DB). Reads route through the current snapshot;
    :meth:`refresh` rebuilds it and swaps it in a single assignment (atomic under
    the asyncio loop). A failed refresh keeps the last-good snapshot. Implements
    the dispatcher's ``RoutingSource`` protocol via :meth:`match`.
    """

    __slots__ = ("_loader", "_lock", "_snapshot")

    def __init__(self, loader: SnapshotLoader) -> None:
        self._loader = loader
        self._snapshot: CacheSnapshot | None = None
        self._lock = asyncio.Lock()

    async def refresh(self) -> None:
        """Reload the snapshot and atomically swap it in (SPEC §6.4).

        On any failure the exception propagates (so the caller can log/metric)
        but the previous snapshot is retained — the write-path keeps serving.
        Concurrent refreshes are serialized so a burst of writes triggers one
        rebuild at a time.
        """
        async with self._lock:
            snapshot = await self._loader()
            self._snapshot = snapshot

    @property
    def snapshot(self) -> CacheSnapshot | None:
        """The current snapshot, or ``None`` before the first successful load."""
        return self._snapshot

    @property
    def is_populated(self) -> bool:
        """Whether a snapshot has been loaded (drives DNS readiness, §11.2)."""
        return self._snapshot is not None

    def match(self, zone: dns.name.Name) -> Route | None:
        """Resolve ``zone`` against the live snapshot (``RoutingSource`` proto)."""
        snapshot = self._snapshot
        if snapshot is None:
            return None
        return snapshot.runtime.routing.match(zone)

    def tsig_key_id_for(self, name: dns.name.Name) -> int | None:
        """Return the row id of the TSIG key named ``name`` (or ``None``)."""
        snapshot = self._snapshot
        if snapshot is None:
            return None
        return snapshot.tsig_key_ids.get(name.canonicalize())

    @property
    def keyring(self) -> Keyring:
        """The current keyring of ``Key`` objects (empty until first load)."""
        snapshot = self._snapshot
        return snapshot.runtime.keyring if snapshot is not None else {}

    @property
    def providers(self) -> list[Provider]:
        """The current provider instances (empty until first load)."""
        snapshot = self._snapshot
        return list(snapshot.runtime.providers) if snapshot is not None else []
