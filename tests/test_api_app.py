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

"""FastAPI app factory / wiring tests (T-M3-01, SPEC §2.2, MED-1).

The app is exercised in-process via ``httpx.ASGITransport`` — no uvicorn, no
sockets. Proves the ``/api/v1`` prefix is served and that ``create_app`` stores
the exact resource instances ``main()`` would own (the no-double-init ownership
invariant, also pinned by T-TEST-15). Throwaway placeholder secrets only.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
import pytest_asyncio
from pydantic import SecretStr

from astropath.api.app import create_app
from astropath.api.deps import AppResources
from astropath.settings import Settings


def make_settings(**overrides: object) -> Settings:
    base: dict[str, object] = {
        "database_dsn": SecretStr("postgresql+asyncpg://u:PLACEHOLDER@localhost/db"),
        "credential_kek": SecretStr("PLACEHOLDER-kek"),
        "admin_password_hash": SecretStr("PLACEHOLDER-argon2"),
        "session_secret": SecretStr("PLACEHOLDER-session-secret-0123456789"),
    }
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


@pytest_asyncio.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(settings=make_settings())
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://astropath.test"
    ) as c:
        yield c


async def test_api_v1_prefix_is_served(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_healthz_liveness(client: httpx.AsyncClient) -> None:
    response = await client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


async def test_readyz_reports_not_ready_without_resources(
    client: httpx.AsyncClient,
) -> None:
    # No cache/db injected -> both planes report not ready (503), body is explicit.
    response = await client.get("/readyz")
    assert response.status_code == 503
    body = response.json()
    assert body["ready"] is False
    assert body["dns"] is False
    assert body["api"] is False


def test_create_app_stores_injected_resources_verbatim() -> None:
    # Ownership invariant (MED-1 / T-TEST-15): the app serves from the exact
    # objects passed in, never a re-created copy. No FastAPI(lifespan=...) hook.
    settings = make_settings()
    sentinel_db = object()
    sentinel_cache = object()
    sentinel_kek = object()
    app = create_app(
        settings=settings,
        database=sentinel_db,  # type: ignore[arg-type]
        cache=sentinel_cache,  # type: ignore[arg-type]
        kek=sentinel_kek,  # type: ignore[arg-type]
    )
    resources: AppResources = app.state.astropath
    assert resources.settings is settings
    assert resources.database is sentinel_db
    assert resources.cache is sentinel_cache
    assert resources.kek is sentinel_kek


def test_app_declares_no_custom_lifespan() -> None:
    # MED-1: main() owns startup/teardown; the app must not attach its own
    # lifespan. FastAPI's default lifespan state is empty (no registered handlers).
    app = create_app(settings=make_settings())
    assert app.router.on_startup == []
    assert app.router.on_shutdown == []


@pytest.mark.parametrize("path", ["/api/v1/health", "/healthz"])
async def test_probe_paths_do_not_require_auth(
    client: httpx.AsyncClient, path: str
) -> None:
    assert (await client.get(path)).status_code == 200


# --------------------------------------------------------------------------- #
# T-M6-04: per-plane readiness truth (DNS sockets/keyring/cache; API = DB up).
# --------------------------------------------------------------------------- #
class _FakeDB:
    """A minimal stand-in exposing only the ping() /readyz calls."""

    def __init__(self, *, reachable: bool) -> None:
        self._reachable = reachable

    async def ping(self) -> None:
        if not self._reachable:
            raise RuntimeError("database unreachable")


async def _readyz(*, dns_ready: bool, db_reachable: bool) -> httpx.Response:
    app = create_app(
        settings=make_settings(),
        database=_FakeDB(reachable=db_reachable),  # type: ignore[arg-type]
        dns_ready=lambda: dns_ready,
    )
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://astropath.test"
    ) as c:
        return await c.get("/readyz")


async def test_readyz_ready_only_when_both_planes_up() -> None:
    response = await _readyz(dns_ready=True, db_reachable=True)
    assert response.status_code == 200
    assert response.json() == {"ready": True, "dns": True, "api": True}


async def test_readyz_not_ready_when_dns_unbound_even_if_api_up() -> None:
    # AC (SPEC §11.2): DNS socket unbound -> not ready even if the API plane is.
    response = await _readyz(dns_ready=False, db_reachable=True)
    assert response.status_code == 503
    assert response.json() == {"ready": False, "dns": False, "api": True}


async def test_readyz_not_ready_when_database_unreachable() -> None:
    response = await _readyz(dns_ready=True, db_reachable=False)
    assert response.status_code == 503
    assert response.json() == {"ready": False, "dns": True, "api": False}
