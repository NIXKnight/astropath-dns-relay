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

import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Response
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST, REGISTRY, CollectorRegistry
from prometheus_client import generate_latest as prometheus_generate_latest

from astropath.api import (
    routes_auth,
    routes_backends,
    routes_domains,
    routes_events,
    routes_tokens,
    routes_tsig,
)
from astropath.api.auth import AuthService, require_admin
from astropath.api.correlation_mw import CorrelationIdMiddleware
from astropath.api.csrf import CsrfOriginMiddleware
from astropath.api.deps import AppResources
from astropath.api.ratelimit import LoginRateLimiter
from astropath.api.session import add_session_middleware
from astropath.cache import RoutingCache
from astropath.crypto import Kek
from astropath.db import Database
from astropath.settings import Settings

__all__ = ["API_V1_PREFIX", "OPENAPI_URL", "create_app"]

API_V1_PREFIX = "/api/v1"
#: Served by our own admin-guarded route (the built-in unauthenticated one is off).
OPENAPI_URL = "/openapi.json"

log = logging.getLogger("astropath.api.app")

#: First path segments the SPA catch-all must never answer with index.html — API
#: and ops routes stay authoritative (an unknown ``/api/v1/*`` returns 404 JSON,
#: not the SPA shell; SPEC §9.3). The docs/ops routes are also registered before
#: the catch-all, so this is defense in depth for their sub-paths.
_SPA_RESERVED_PREFIXES = frozenset(
    {"api", "docs", "redoc", "openapi.json", "metrics", "healthz", "readyz", "assets"}
)


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
    dns_ready: Callable[[], bool] | None = None,
    static_dir: str | Path | None = None,
) -> FastAPI:
    """Build the management-plane FastAPI app from ``main()``-owned resources.

    No ``lifespan=`` is attached (MED-1): uvicorn runs with ``lifespan="off"`` and
    ``main()`` owns every resource. The passed instances are stored verbatim on
    ``app.state.astropath`` — the app serves from exactly those objects, never a
    re-created copy (the ownership invariant T-TEST-15 asserts).
    """
    # Disable FastAPI's built-in (unauthenticated) docs + schema routes; they are
    # re-registered below behind require_admin (MED-6). /metrics, /healthz, /readyz
    # are added explicitly with their own auth posture.
    app = FastAPI(
        title="AstropathDNSRelay",
        version="0.1.0",
        summary="Self-hosted ACME DNS-01 solver gateway management API.",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.astropath = AppResources(
        settings=settings,
        database=database,
        cache=cache,
        kek=kek,
        metrics_registry=metrics_registry,
        dns_readiness=dns_ready,
        auth=AuthService(database, settings),
        rate_limiter=LoginRateLimiter(),
    )

    # Signed (not encrypted) session cookie carrying only an opaque admin marker.
    add_session_middleware(app, settings)
    # CSRF origin check for cookie-authenticated mutating requests (added after the
    # session middleware so it runs first — outermost — and rejects a forged
    # cross-origin write before any handler work).
    app.add_middleware(CsrfOriginMiddleware, allowed_origin=settings.management_origin)
    # Correlation id (T-M6-03): added LAST so it is the outermost middleware — it
    # binds the id before session/CSRF run (so even a rejected request is
    # traceable) and echoes X-Correlation-ID on every response (SPEC §11.4).
    app.add_middleware(CorrelationIdMiddleware)

    app.include_router(_meta_router())
    app.include_router(routes_auth.router)
    app.include_router(routes_backends.router)
    app.include_router(routes_domains.router)
    app.include_router(routes_tsig.router)
    app.include_router(routes_tokens.router)
    app.include_router(routes_events.router)

    # --- API schema + interactive docs, admin-only (MED-6) --------------------- #
    # These are LAN-only *and* auth-gated: do not rely on /api/v1 protection to
    # cover them. The browser loads /docs (session cookie) which then fetches the
    # schema from OPENAPI_URL with the same cookie, so both stay behind require_admin.
    @app.get(
        OPENAPI_URL, include_in_schema=False, dependencies=[Depends(require_admin)]
    )
    async def openapi_schema() -> dict[str, Any]:
        return app.openapi()

    @app.get("/docs", include_in_schema=False, dependencies=[Depends(require_admin)])
    async def swagger_ui() -> HTMLResponse:
        return get_swagger_ui_html(
            openapi_url=OPENAPI_URL, title=f"{app.title} - Swagger UI"
        )

    @app.get("/redoc", include_in_schema=False, dependencies=[Depends(require_admin)])
    async def redoc_ui() -> HTMLResponse:
        return get_redoc_html(openapi_url=OPENAPI_URL, title=f"{app.title} - ReDoc")

    # --- Prometheus scrape, unauthenticated but LAN-only (MED-6) --------------- #
    # Folds the M1 interim start_http_server into the app: exposes the *same*
    # registry main() writes to, so every data-plane metric name is preserved.
    # Prometheus exposition carries only metric names + non-secret label values.
    @app.get("/metrics", include_in_schema=False)
    async def metrics() -> Response:
        resources: AppResources = app.state.astropath
        registry = (
            resources.metrics_registry
            if resources.metrics_registry is not None
            else REGISTRY
        )
        return Response(
            prometheus_generate_latest(registry), media_type=CONTENT_TYPE_LATEST
        )

    @app.get("/healthz", tags=["probes"], summary="Liveness (process up)")
    async def healthz() -> dict[str, str]:
        # Liveness only — the process is up and serving (SPEC §11.2). Per-plane
        # readiness (sockets/keyring/cache/DB) is /readyz.
        return {"status": "ok"}

    @app.get("/readyz", tags=["probes"], summary="Per-plane readiness")
    async def readyz(response: Response) -> dict[str, object]:
        # Per-plane truth (SPEC §11.2, T-M6-04): DNS is ready only when its
        # UDP+TCP sockets are bound AND the keyring is loaded AND the routing
        # cache is populated (the injected dns_readiness probe); the management
        # plane is ready when the database answers. Overall ready needs both.
        resources: AppResources = app.state.astropath
        if resources.dns_readiness is not None:
            dns_ready = resources.dns_readiness()
        else:  # pure-app fallback: cache population alone
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

    # SPA serving (SPEC §9.3, T-M4-04) — registered LAST so the catch-all never
    # shadows an API/ops route above. Disabled (the app still boots) when no built
    # SPA is present; the dev workflow uses the Vite proxy instead.
    _configure_spa(app, static_dir=static_dir, settings=settings)

    return app


def _configure_spa(
    app: FastAPI, *, static_dir: str | Path | None, settings: Settings
) -> None:
    """Mount the built admin SPA behind an explicit catch-all (SPEC §9.3).

    The directory comes from the ``static_dir`` argument (tests pass a fixture
    dist) or, when absent, ``settings.spa_dir`` (``/app/static`` in the image). If
    neither is set the SPA is simply not served (dev/pure-API). If a directory is
    configured but has no ``index.html`` the app still boots, logging one line and
    serving the API/ops surface only (the AC for a missing runtime dist).
    """
    source = static_dir if static_dir is not None else settings.spa_dir
    if source is None:
        return  # SPA serving not configured (dev proxy / API-only tests).
    root = Path(source)
    index = root / "index.html"
    if not index.is_file():
        log.warning("SPA directory %r has no index.html; serving API only", str(root))
        return
    _register_spa(app, root=root, index=index)
    log.info("serving admin SPA from %s", root)


def _register_spa(app: FastAPI, *, root: Path, index: Path) -> None:
    """Mount hashed assets and register the deep-link catch-all (SPEC §9.3).

    ``StaticFiles(html=True)`` alone only serves a directory's ``index.html`` for
    directory URLs — a deep link like ``/backends/5`` would 404. So the built
    ``assets/`` are mounted for correct content types, and an explicit catch-all
    returns a real file when one exists (favicon, robots) else ``index.html`` for
    any non-reserved path. Reserved API/ops prefixes return 404 JSON so unknown
    ``/api/v1/*`` paths are never masked by the SPA shell.
    """
    assets = root / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=assets), name="assets")

    root_resolved = root.resolve()

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa(full_path: str) -> FileResponse:
        first_segment = full_path.split("/", 1)[0]
        if first_segment in _SPA_RESERVED_PREFIXES:
            raise HTTPException(status_code=404, detail="Not Found")
        if full_path:
            candidate = (root / full_path).resolve()
            if candidate.is_file() and candidate.is_relative_to(root_resolved):
                return FileResponse(candidate)
        return FileResponse(index)
