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

"""Injected resources and FastAPI dependencies for the management plane (MED-1).

``main()`` is the single owner of every shared resource (SPEC §2.2). The FastAPI
app never creates a database engine, KEK, cache, or HTTP client — it receives them
from ``main()`` via :class:`AppResources`, stashed on ``app.state`` by
:func:`~astropath.api.app.create_app`, and reads them through the dependency
accessors below. This is what T-TEST-15 pins: no ``FastAPI(lifespan=...)``, no
double-init; the objects the app serves from are the exact instances ``main()``
constructed.

Tests either inject fakes into :class:`AppResources` or override individual
dependencies via ``app.dependency_overrides`` — so the auth matrix and CRUD flows
are exercised without standing up uvicorn.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

from fastapi import Request
from prometheus_client import CollectorRegistry
from sqlalchemy.ext.asyncio import AsyncSession

from astropath.api.ratelimit import LoginRateLimiter
from astropath.cache import RoutingCache
from astropath.crypto import Kek
from astropath.db import Database
from astropath.settings import Settings

__all__ = [
    "AppResources",
    "get_cache",
    "get_database",
    "get_kek",
    "get_optional_cache",
    "get_rate_limiter",
    "get_resources",
    "get_session",
    "get_settings_dep",
    "refresh_routing_cache",
]

logger = logging.getLogger(__name__)


@dataclass
class AppResources:
    """The shared resources ``main()`` owns and injects into the app (MED-1).

    ``database``/``cache``/``kek`` are optional so a pure-app test (auth matrix,
    session assertions) can build the app without a live Postgres; the CRUD routes
    fail loudly if their resource is genuinely absent at request time. Auth and
    the login rate limiter are attached as attributes by later wiring (T-M3-02,
    T-M3-07) and typed :class:`~typing.Any` here to keep this bundle free of the
    auth/CRUD import graph.
    """

    settings: Settings
    database: Database | None = None
    cache: RoutingCache | None = None
    kek: Kek | None = None
    metrics_registry: CollectorRegistry | None = None
    #: Set by create_app once the auth plane lands (T-M3-02); an ``AuthService``.
    auth: Any = None
    #: Set by create_app once rate limiting lands (T-M3-07); a ``LoginRateLimiter``.
    rate_limiter: Any = None


def get_resources(request: Request) -> AppResources:
    """Return the :class:`AppResources` bundle stored on ``app.state``."""
    resources: AppResources = request.app.state.astropath
    return resources


def get_settings_dep(request: Request) -> Settings:
    """Injected process settings (never re-parsed per request)."""
    return get_resources(request).settings


def get_database(request: Request) -> Database:
    """Injected :class:`~astropath.db.Database` (owned by ``main()``)."""
    database = get_resources(request).database
    if database is None:  # pragma: no cover - guarded by startup validation
        raise RuntimeError("database is not configured for this app instance")
    return database


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding one AsyncSession per request (SPEC §12.2)."""
    async with get_database(request).session() as session:
        yield session


def get_cache(request: Request) -> RoutingCache:
    """Injected DB-backed :class:`~astropath.cache.RoutingCache` (MED-2)."""
    cache = get_resources(request).cache
    if cache is None:  # pragma: no cover - guarded by startup validation
        raise RuntimeError("routing cache is not configured for this app instance")
    return cache


def get_optional_cache(request: Request) -> RoutingCache | None:
    """Return the routing cache if this app instance has one, else ``None``.

    Unlike :func:`get_cache` this never raises — the cache-refresh hook is a
    best-effort convergence signal (MED-2, T-M3-16), and pure-app tests that run
    without a cache must still exercise the CRUD write path.
    """
    return get_resources(request).cache


async def refresh_routing_cache(cache: RoutingCache | None) -> None:
    """Reload the in-memory routing cache after a routing/keyring write (T-M3-16).

    Called *after* the write has committed, so the row is already durable and the
    data plane's source of truth is correct regardless of what happens here. A
    successful refresh makes the change visible to the DNS plane immediately, with
    no restart (the AC). On failure the last-good snapshot is retained and the
    periodic refresher (T-M2-05) reconverges, so the error is logged, not raised —
    a transient DB hiccup during refresh must not fail an already-committed write.
    """
    if cache is None:
        return
    try:
        await cache.refresh()
    except Exception:  # pragma: no cover - defensive; periodic refresh reconverges
        logger.warning(
            "routing cache refresh after management-API write failed", exc_info=True
        )


def get_kek(request: Request) -> Kek:
    """Injected :class:`~astropath.crypto.Kek` for encrypt-on-write CRUD."""
    kek = get_resources(request).kek
    if kek is None:  # pragma: no cover - guarded by startup validation
        raise RuntimeError("credential KEK is not configured for this app instance")
    return kek


def get_rate_limiter(request: Request) -> LoginRateLimiter:
    """Injected in-process login rate limiter (SPEC §8.5)."""
    limiter: LoginRateLimiter = get_resources(request).rate_limiter
    return limiter
