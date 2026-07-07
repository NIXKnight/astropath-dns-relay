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

"""FastAPI application factory and router wiring (SPEC §2.2, §9, MED-1).

:func:`create_app` builds the management-plane app from resources ``main()``
already owns (SPEC §2.2) — it never constructs an engine, KEK, cache, or HTTP
client itself. The app runs embedded under uvicorn with ``lifespan="off"``, so
there is exactly one owner of startup/teardown and no double-init (T-TEST-15).

Route composition order matters (SPEC §9.3): API routers and real asset mounts
are registered first; the SPA catch-all (M4, T-M4-04) is registered last. This
module leaves that seam clean — it mounts only the ``/api/v1`` routers and the
probe endpoints, so M4 can append the static mount + catch-all without reordering.
"""

from __future__ import annotations

from fastapi import APIRouter, FastAPI, Response
from prometheus_client import CollectorRegistry

from astropath.api import routes_auth
from astropath.api.auth import AuthService
from astropath.api.deps import AppResources
from astropath.api.session import add_session_middleware
from astropath.cache import RoutingCache
from astropath.crypto import Kek
from astropath.db import Database
from astropath.settings import Settings

__all__ = ["API_V1_PREFIX", "create_app"]

API_V1_PREFIX = "/api/v1"


def _meta_router() -> APIRouter:
    """The ``/api/v1`` liveness route (proves the prefix is served, T-M3-01)."""
    router = APIRouter(prefix=API_V1_PREFIX, tags=["meta"])

    @router.get("/health", summary="API liveness")
    async def api_health() -> dict[str, str]:
        return {"status": "ok"}

    return router


def create_app(
    *,
    settings: Settings,
    database: Database | None = None,
    cache: RoutingCache | None = None,
    kek: Kek | None = None,
    metrics_registry: CollectorRegistry | None = None,
) -> FastAPI:
    """Build the management-plane FastAPI app from ``main()``-owned resources.

    No ``lifespan=`` is attached (MED-1): uvicorn runs with ``lifespan="off"`` and
    ``main()`` owns every resource. The passed instances are stored verbatim on
    ``app.state.astropath`` — the app serves from exactly those objects, never a
    re-created copy (the ownership invariant T-TEST-15 asserts).
    """
    app = FastAPI(
        title="AstropathDNSRelay",
        version="0.1.0",
        summary="Self-hosted ACME DNS-01 solver gateway management API.",
    )
    app.state.astropath = AppResources(
        settings=settings,
        database=database,
        cache=cache,
        kek=kek,
        metrics_registry=metrics_registry,
        auth=AuthService(database, settings),
    )

    # Signed (not encrypted) session cookie carrying only an opaque admin marker.
    add_session_middleware(app, settings)

    app.include_router(_meta_router())
    app.include_router(routes_auth.router)

    @app.get("/healthz", tags=["probes"], summary="Liveness (process up)")
    async def healthz() -> dict[str, str]:
        # Liveness only — the process is up and serving (SPEC §11.2). Per-plane
        # readiness is /readyz; full per-plane detail lands in T-M6-04.
        return {"status": "ok"}

    @app.get("/readyz", tags=["probes"], summary="Per-plane readiness")
    async def readyz(response: Response) -> dict[str, object]:
        resources: AppResources = app.state.astropath
        dns_ready = resources.cache is not None and resources.cache.is_populated
        api_ready = False
        if resources.database is not None:
            try:
                await resources.database.ping()
                api_ready = True
            except Exception:
                api_ready = False
        ready = bool(dns_ready and api_ready)
        if not ready:
            response.status_code = 503
        return {"ready": ready, "dns": dns_ready, "api": api_ready}

    return app
