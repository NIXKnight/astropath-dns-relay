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

"""Docs / OpenAPI / metrics auth boundary (T-M3-14, SPEC §11, MED-6).

``/docs`` + ``/redoc`` + ``/openapi.json`` sit behind ``require_admin`` (the
built-in unauthenticated routes are disabled). ``/metrics`` is unauthenticated but
serves the *same* registry ``main()`` writes to (the M1 interim ``start_http_server``
folded into the app), preserving every metric name and exposing no secrets.
``/healthz`` + ``/readyz`` stay unauthenticated. The auth-required cases need no
database; the auth-granted cases seed an ``X-API-Key`` (Docker-gated).
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest_asyncio
from prometheus_client import CollectorRegistry
from tests._api import api_client, seed_api_token
from tests.test_api_app import make_settings

from astropath.api.app import create_app
from astropath.db import Database
from astropath.observability import DataPlaneMetrics

# Placeholder secrets carried by make_settings — none may appear in a scrape.
_CONFIGURED_SECRETS = (
    "PLACEHOLDER-session-secret-0123456789",
    "PLACEHOLDER-kek",
    "PLACEHOLDER-argon2",
)


@pytest_asyncio.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    """Pure app (no DB) with a populated metrics registry."""
    registry = CollectorRegistry()
    DataPlaneMetrics(registry=registry)  # registers the data-plane metric families
    app = create_app(settings=make_settings(), metrics_registry=registry)
    async with api_client(app) as c:
        yield c


@pytest_asyncio.fixture
async def authed_client(api_db: Database) -> AsyncIterator[httpx.AsyncClient]:
    registry = CollectorRegistry()
    DataPlaneMetrics(registry=registry)
    app = create_app(
        settings=make_settings(), database=api_db, metrics_registry=registry
    )
    headers = await seed_api_token(api_db)
    async with api_client(app) as c:
        c.headers.update(headers)
        yield c


# --------------------------------------------------------------------------- #
# /docs + /openapi.json require auth (do not rely on /api/v1 protection).
# --------------------------------------------------------------------------- #
async def test_openapi_schema_requires_auth(client: httpx.AsyncClient) -> None:
    assert (await client.get("/openapi.json")).status_code == 401


async def test_docs_require_auth(client: httpx.AsyncClient) -> None:
    # 401 (guarded), not 404 — proves the built-in unauthenticated docs are off
    # and replaced by an auth-gated route, not simply removed.
    assert (await client.get("/docs")).status_code == 401
    assert (await client.get("/redoc")).status_code == 401


async def test_openapi_schema_accessible_with_auth(
    authed_client: httpx.AsyncClient,
) -> None:
    response = await authed_client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    assert schema["info"]["title"] == "astropath-dns-relay"
    assert "/api/v1/backends" in schema["paths"]


async def test_docs_accessible_with_auth(authed_client: httpx.AsyncClient) -> None:
    response = await authed_client.get("/docs")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "swagger-ui" in response.text.lower()

    redoc = await authed_client.get("/redoc")
    assert redoc.status_code == 200
    assert redoc.headers["content-type"].startswith("text/html")


# --------------------------------------------------------------------------- #
# /metrics: unauthenticated, prometheus format, all metric names, no secrets.
# --------------------------------------------------------------------------- #
async def test_metrics_is_unauthenticated_prometheus(client: httpx.AsyncClient) -> None:
    response = await client.get("/metrics")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    body = response.text
    # Every data-plane metric family name is preserved through the fold (counters
    # carry the client's _total suffix in the exposition).
    assert "# TYPE astropath_challenges_total counter" in body
    assert "astropath_provider_call_duration_seconds" in body
    assert "astropath_plane_unhealthy" in body
    assert "astropath_zone_last_success_timestamp" in body


async def test_metrics_exposes_no_configured_secrets(
    client: httpx.AsyncClient,
) -> None:
    body = (await client.get("/metrics")).text
    for secret in _CONFIGURED_SECRETS:
        assert secret not in body


async def test_metrics_without_registry_serves_process_default() -> None:
    app = create_app(settings=make_settings())  # no registry injected
    async with api_client(app) as c:
        response = await c.get("/metrics")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")


# --------------------------------------------------------------------------- #
# /healthz + /readyz stay unauthenticated.
# --------------------------------------------------------------------------- #
async def test_probes_are_unauthenticated(client: httpx.AsyncClient) -> None:
    assert (await client.get("/healthz")).status_code == 200
    # readyz answers without auth (503 when resources are absent), never 401.
    assert (await client.get("/readyz")).status_code in (200, 503)
