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

"""Process entrypoint / lifecycle tests (T-M1-24, SPEC §2.1, HIGH-1, MED-1).

The database is the only backend: ``serve()`` runs both planes with the DB-backed
routing cache as the sole keyring/routing source. Tests inject a shutdown event
and disable signals so they never touch the process-wide signal table; the
serve() suites are Docker-gated via the shared migrated Postgres (``api_db``
truncates every table, so the DB-sourced keyring starts EMPTY). Throwaway key
material only.
"""

from __future__ import annotations

import asyncio
import socket

import dns.query
import dns.rcode
import dns.update
import httpx
import pytest
from pydantic import SecretStr

from astropath import main as main_module
from astropath.crypto import generate_key
from astropath.db import Database
from astropath.main import main, serve
from astropath.settings import Settings

# Placeholder DSN for the no-DB unit path (main() fails on the KEK before any IO).
_DSN = "postgresql+asyncpg://astropath:PLACEHOLDER@localhost:5432/astropath"


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _serve_settings(
    *,
    kek_raw: str,
    dsn: str,
    dns_port: int,
    http_port: int,
) -> Settings:
    return Settings(
        credential_kek=SecretStr(kek_raw),
        database_dsn=SecretStr(dsn),
        admin_password_hash=SecretStr("PLACEHOLDER-argon2-hash"),
        session_secret=SecretStr("PLACEHOLDER-session-secret-0123456789"),
        dns_bind="127.0.0.1",
        dns_port=dns_port,
        http_bind="127.0.0.1",
        http_port=http_port,
    )


async def _await_bound(port: int, *, timeout: float = 3.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        try:
            _reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.close()
            await writer.wait_closed()
            return
        except OSError:
            if loop.time() >= deadline:
                raise
            await asyncio.sleep(0.02)


async def _await_ready(base_url: str, *, timeout: float = 15.0) -> dict[str, object]:
    """Poll ``/readyz`` until it answers 200 (both planes ready); return the body."""
    async with httpx.AsyncClient(timeout=2.0) as probe:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while True:
            try:
                resp = await probe.get(f"{base_url}/readyz")
                if resp.status_code == 200:
                    body: dict[str, object] = resp.json()
                    return body
            except httpx.HTTPError:
                pass  # uvicorn not accepting yet — keep polling until the deadline
            if loop.time() >= deadline:
                raise AssertionError("serve() did not reach readiness in time")
            await asyncio.sleep(0.05)


def test_main_returns_2_on_startup_validation_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # main() maps a StartupError to exit 2 before any bind. The KEK is required
    # (it decrypts the DB secrets), so an unset KEK trips validate_kek before any
    # database IO — no Docker needed for this path.
    settings = _serve_settings(kek_raw="", dsn=_DSN, dns_port=0, http_port=0)
    monkeypatch.setattr(main_module, "get_settings", lambda: settings)
    monkeypatch.setattr(main_module, "configure_logging", lambda _s: None)

    assert main() == 2


# --------------------------------------------------------------------------- #
# serve() (two-plane DB mode) — Docker-gated via the shared migrated Postgres.
# api_db truncates every table, so the DB-sourced keyring starts EMPTY.
# --------------------------------------------------------------------------- #
async def test_serve_reaches_ready_and_notauths_empty_keyring(
    api_db: Database, pg_migrated: str
) -> None:
    # The database is the only backend: with a truncated DB the keyring is EMPTY,
    # yet readiness still reports the DNS plane loaded (empty-but-initialized), and
    # the data plane answers an unsigned UPDATE with NOTAUTH — zero keys configured
    # (SPEC §11 / T-M6-04). The listener binds ASTROPATH_DNS_BIND / ASTROPATH_DNS_PORT.
    kek_raw = generate_key()
    dns_port, http_port = _free_port(), _free_port()
    settings = _serve_settings(
        kek_raw=kek_raw, dsn=pg_migrated, dns_port=dns_port, http_port=http_port
    )
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _r: httpx.Response(200))
    )
    shutdown = asyncio.Event()
    serve_task = asyncio.create_task(
        serve(settings, shutdown=shutdown, install_signals=False, http_client=client)
    )
    try:
        await _await_bound(dns_port)
        await _await_bound(http_port)
        assert await _await_ready(f"http://127.0.0.1:{http_port}") == {
            "ready": True,
            "dns": True,  # empty-but-initialized keyring counts as loaded
            "api": True,
        }

        unsigned = dns.update.UpdateMessage("example.com.")
        unsigned.add("_acme-challenge.example.com.", 300, "TXT", "tok")
        response = await asyncio.to_thread(
            dns.query.udp, unsigned, "127.0.0.1", 5.0, dns_port
        )
        assert response.rcode() == dns.rcode.NOTAUTH  # empty keyring rejects
    finally:
        shutdown.set()

    assert await asyncio.wait_for(serve_task, timeout=10.0) == 0  # clean stop
    await client.aclose()


async def test_serve_returns_unhealthy_when_plane_exhausts_budget(
    api_db: Database, pg_migrated: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A plane whose supervisor spends its restart budget makes serve() return 1
    # (surface unhealthy so the orchestrator restarts the whole process). The
    # stubbed supervise never binds sockets; the DB preconditions still pass first.
    async def _gave_up(
        name: str,
        factory: object,
        shutdown: asyncio.Event,
        limiter: object,
        metrics: object,
        *,
        sleep: object = None,
    ) -> None:
        shutdown.set()  # supervisor spent its budget: flag + shutdown, then return

    monkeypatch.setattr(main_module, "supervise", _gave_up)

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _r: httpx.Response(200))
    )
    settings = _serve_settings(
        kek_raw=generate_key(),
        dsn=pg_migrated,
        dns_port=_free_port(),
        http_port=_free_port(),
    )
    exit_code = await serve(
        settings,
        shutdown=asyncio.Event(),
        install_signals=False,
        http_client=client,
    )
    await client.aclose()

    assert exit_code == 1  # a plane gave up -> surface unhealthy
