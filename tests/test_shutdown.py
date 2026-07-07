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

"""Supervisor + graceful-shutdown suite (T-TEST-14, SPEC §2/§3, HIGH-1).

Failure isolation, bounded restart, and the unhealthy gauge are covered by
:mod:`tests.test_supervisor` (the ``supervise`` primitive) and
:mod:`tests.test_server` (the server drain mechanics). This suite proves the
integrated behavior: a SIGTERM drains an in-flight challenge before teardown,
the drain is bounded when a provider hangs, and per-plane readiness transitions
with the DNS socket bind. Throwaway key material only.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator
from pathlib import Path

import dns.name
import dns.query
import dns.rcode
import dns.tsig
import httpx
import pytest
from prometheus_client import CollectorRegistry
from pydantic import SecretStr
from tests.test_api_app import _FakeDB, make_settings
from tests.test_main import _await_bound, _free_port, _signed_update, _write_bootstrap
from tests.test_server import StubDispatcher

from astropath.api.app import create_app
from astropath.crypto import Kek, generate_key
from astropath.data_plane.server import Rfc2136Server
from astropath.main import run
from astropath.observability import DataPlaneMetrics
from astropath.settings import Settings

Keyring = dict[dns.name.Name, dns.tsig.Key]

_DSN = "postgresql+asyncpg://astropath:PLACEHOLDER@localhost:5432/astropath"


def _settings(path: Path, kek_raw: str, *, port: int, drain: float = 2.0) -> Settings:
    return Settings(
        credential_kek=SecretStr(kek_raw),
        database_dsn=SecretStr(_DSN),
        admin_password_hash=SecretStr("PLACEHOLDER-argon2-hash"),
        session_secret=SecretStr("PLACEHOLDER-session-secret"),
        bootstrap_path=str(path),
        metrics_port=0,
        dns_port=port,
        shutdown_drain_timeout=drain,
    )


# --------------------------------------------------------------------------- #
# SIGTERM full drain order: an in-flight challenge finishes before teardown.
# --------------------------------------------------------------------------- #
async def test_sigterm_drains_in_flight_challenge(
    tmp_path: Path, keyring: Keyring
) -> None:
    kek_raw = generate_key()
    port = _free_port()
    path = tmp_path / "astropath.bootstrap.toml"
    _write_bootstrap(path, Kek([kek_raw]), port=port)

    entered = asyncio.Event()
    release = asyncio.Event()
    captured: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        entered.set()
        await release.wait()  # hold the provider call in flight across shutdown
        return httpx.Response(200, text="good")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    shutdown = asyncio.Event()
    run_task = asyncio.create_task(
        run(
            _settings(path, kek_raw, port=port, drain=5.0),
            shutdown=shutdown,
            install_signals=False,
            http_client=client,
        )
    )

    response = None
    try:
        await _await_bound(port)
        query_task = asyncio.create_task(
            asyncio.to_thread(
                dns.query.tcp, _signed_update(keyring), "127.0.0.1", 5.0, port
            )
        )
        await asyncio.wait_for(entered.wait(), timeout=5.0)  # provider is in flight

        shutdown.set()  # SIGTERM arrives mid-dispatch
        await asyncio.sleep(0.1)
        assert not run_task.done()  # draining, not exited — the reply is not dropped

        release.set()  # let the in-flight call complete
        response = await asyncio.wait_for(query_task, timeout=5.0)
    finally:
        release.set()
        shutdown.set()

    exit_code = await asyncio.wait_for(run_task, timeout=5.0)
    await client.aclose()

    assert exit_code == 0  # clean, drained shutdown
    assert response is not None and response.rcode() == dns.rcode.NOERROR
    assert len(captured) == 1  # the in-flight provider call actually completed


# --------------------------------------------------------------------------- #
# Bounded drain: a hung provider must not block the process from exiting.
# --------------------------------------------------------------------------- #
async def test_sigterm_shutdown_is_bounded_when_provider_hangs(
    tmp_path: Path, keyring: Keyring
) -> None:
    kek_raw = generate_key()
    port = _free_port()
    path = tmp_path / "astropath.bootstrap.toml"
    _write_bootstrap(path, Kek([kek_raw]), port=port)

    entered = asyncio.Event()
    forever = asyncio.Event()  # never set — the provider hangs

    async def handler(request: httpx.Request) -> httpx.Response:
        entered.set()
        await forever.wait()
        return httpx.Response(200, text="good")  # pragma: no cover

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    shutdown = asyncio.Event()
    run_task = asyncio.create_task(
        run(
            _settings(path, kek_raw, port=port, drain=0.5),
            shutdown=shutdown,
            install_signals=False,
            http_client=client,
        )
    )

    query_task: asyncio.Task[object] | None = None
    try:
        await _await_bound(port)
        query_task = asyncio.create_task(
            asyncio.to_thread(
                dns.query.tcp, _signed_update(keyring), "127.0.0.1", 5.0, port
            )
        )
        await asyncio.wait_for(entered.wait(), timeout=5.0)
        shutdown.set()

        # Despite the hung provider, the bounded drain (0.5s) lets run() exit.
        exit_code = await asyncio.wait_for(run_task, timeout=5.0)
        assert exit_code == 0
    finally:
        forever.set()
        shutdown.set()
        if query_task is not None:
            query_task.cancel()
            with contextlib.suppress(BaseException):
                await query_task
        await client.aclose()


# --------------------------------------------------------------------------- #
# Per-plane readiness transitions: /readyz.dns tracks the DNS socket bind.
# --------------------------------------------------------------------------- #
@pytest.fixture
async def readiness_client(
    keyring: Keyring,
) -> AsyncIterator[tuple[httpx.AsyncClient, Rfc2136Server]]:
    server = Rfc2136Server(
        keyring,
        StubDispatcher(),
        DataPlaneMetrics(registry=CollectorRegistry()),
        host="127.0.0.1",
        port=0,
    )

    def _dns_ready() -> bool:
        # The exact composition main() wires: sockets bound AND keyring loaded
        # AND routing cache populated (cache treated as populated here).
        return server.is_accepting and bool(keyring)

    app = create_app(
        settings=make_settings(),
        database=_FakeDB(reachable=True),  # type: ignore[arg-type]
        dns_ready=_dns_ready,
    )
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://astropath.test"
    ) as client:
        yield client, server


async def test_readyz_dns_field_tracks_socket_bind(
    readiness_client: tuple[httpx.AsyncClient, Rfc2136Server],
) -> None:
    client, server = readiness_client

    # Before bind: DNS not ready (overall not ready) even though the API plane is.
    body = (await client.get("/readyz")).json()
    assert body == {"ready": False, "dns": False, "api": True}

    ready = asyncio.Event()
    task = asyncio.create_task(server.serve(ready=ready))
    await asyncio.wait_for(ready.wait(), timeout=5.0)
    try:
        # Bound: both planes ready.
        body = (await client.get("/readyz")).json()
        assert body == {"ready": True, "dns": True, "api": True}

        # Draining: DNS flips back to not ready.
        server.stop_accepting()
        body = (await client.get("/readyz")).json()
        assert body["dns"] is False and body["ready"] is False
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
