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

Throwaway key material only (SPEC secret discipline). ``run()`` is exercised
with an injected shutdown event and signals disabled so tests never touch the
process-wide signal table.
"""

from __future__ import annotations

import asyncio
import base64
import socket
from pathlib import Path
from urllib.parse import parse_qs

import dns.name
import dns.query
import dns.rcode
import dns.tsig
import dns.update
import httpx
import pytest
from pydantic import SecretStr

from astropath import main as main_module
from astropath.crypto import Kek, generate_key
from astropath.db import Database
from astropath.main import main, run, serve
from astropath.settings import Settings

Keyring = dict[dns.name.Name, dns.tsig.Key]

# Equals conftest SECRET_B64, so the cm-key. keyring fixture signs the same key
# the bootstrap file provisions.
_TSIG_SECRET = base64.b64encode(b"0123456789abcdef0123456789abcdef").decode()
_HE_KEY = "THROWAWAY-he-dynamic-key"


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _write_bootstrap(path: Path, kek: Kek, *, port: int) -> None:
    path.write_text(
        "[listener]\n"
        'host = "127.0.0.1"\n'
        f"port = {port}\n\n"
        "[[tsig_keys]]\n"
        'name = "cm-key."\n'
        'algorithm = "hmac-sha256"\n'
        f'secret = "{kek.encrypt_str(_TSIG_SECRET)}"\n\n'
        "[[zones]]\n"
        'zone = "example.com."\n'
        'provider = "hurricane"\n'
        'record_name = "_acme-challenge.example.com."\n'
        f'he_dynamic_key = "{kek.encrypt_str(_HE_KEY)}"\n',
        encoding="utf-8",
    )


# Placeholder M2/M3 secrets: the full env carries them from M0 (.env.example),
# but the M1 data plane never reads them. Obvious throwaway values only.
_DSN = "postgresql+asyncpg://astropath:PLACEHOLDER@localhost:5432/astropath"


def _make_settings(kek_raw: str, bootstrap_path: str | None, *, port: int) -> Settings:
    return Settings(
        credential_kek=SecretStr(kek_raw),
        database_dsn=SecretStr(_DSN),
        admin_password_hash=SecretStr("PLACEHOLDER-argon2-hash"),
        session_secret=SecretStr("PLACEHOLDER-session-secret"),
        bootstrap_path=bootstrap_path,
        metrics_port=0,  # ephemeral Prometheus port for the test
        dns_port=port,
    )


def _settings(path: Path, kek_raw: str, *, port: int) -> Settings:
    return _make_settings(kek_raw, str(path), port=port)


def _signed_update(keyring: Keyring) -> dns.update.UpdateMessage:
    query = dns.update.UpdateMessage(
        "example.com.",
        keyname=dns.name.from_text("cm-key."),
        keyring=keyring,
        keyalgorithm=dns.tsig.HMAC_SHA256,
    )
    query.add("_acme-challenge.example.com.", 300, "TXT", "token-value")
    return query


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


async def test_run_serves_signed_update_then_shuts_down_cleanly(
    tmp_path: Path, keyring: Keyring
) -> None:
    kek_raw = generate_key()
    port = _free_port()
    path = tmp_path / "astropath.bootstrap.toml"
    _write_bootstrap(path, Kek([kek_raw]), port=port)

    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, text="good")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    shutdown = asyncio.Event()
    run_task = asyncio.create_task(
        run(
            _settings(path, kek_raw, port=port),
            shutdown=shutdown,
            install_signals=False,
            http_client=client,
        )
    )

    try:
        await _await_bound(port)
        # dns.query.tcp signs the request and verifies the signed response,
        # chaining the request MAC — the proof the reply is TSIG-signed.
        response = await asyncio.to_thread(
            dns.query.tcp, _signed_update(keyring), "127.0.0.1", 5.0, port
        )
    finally:
        shutdown.set()

    exit_code = await asyncio.wait_for(run_task, timeout=5.0)

    assert exit_code == 0  # clean, shutdown-driven stop
    assert response.rcode() == dns.rcode.NOERROR  # verified UPDATE dispatched
    assert response.had_tsig is True  # reply verified against the request MAC
    form = {k: v[0] for k, v in parse_qs(captured[0].content.decode()).items()}
    assert form["txt"] == "token-value"  # challenge reached HE
    assert form["password"] == _HE_KEY  # per-record key injected from the file
    assert not client.is_closed  # an injected client is owned by the caller


async def test_run_closes_the_http_client_it_owns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    kek_raw = generate_key()
    port = _free_port()
    path = tmp_path / "astropath.bootstrap.toml"
    _write_bootstrap(path, Kek([kek_raw]), port=port)

    owned = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _r: httpx.Response(200))
    )
    monkeypatch.setattr(main_module, "build_async_client", lambda: owned)

    shutdown = asyncio.Event()
    run_task = asyncio.create_task(
        run(
            _settings(path, kek_raw, port=port),
            shutdown=shutdown,
            install_signals=False,
        )
    )
    await _await_bound(port)  # ensure it bound before we tear down
    shutdown.set()

    assert await asyncio.wait_for(run_task, timeout=5.0) == 0
    assert owned.is_closed  # main() disposed the client it created


async def test_run_returns_unhealthy_when_plane_exhausts_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    kek_raw = generate_key()
    port = _free_port()
    path = tmp_path / "astropath.bootstrap.toml"
    _write_bootstrap(path, Kek([kek_raw]), port=port)

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
    exit_code = await run(
        _settings(path, kek_raw, port=port),
        shutdown=asyncio.Event(),
        install_signals=False,
        http_client=client,
    )
    await client.aclose()

    assert exit_code == 1  # surfaces unhealthy so the orchestrator restarts us


def test_main_returns_2_on_startup_validation_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # main() maps a StartupError to exit 2 before any bind. The KEK is required in
    # BOTH modes (it decrypts DB secrets too), so an unset KEK still hard-fails —
    # unlike the now-optional bootstrap file, whose absence is a valid DB-mode boot
    # (serve(), SPEC §10/§16). An empty KEK trips validate_and_load before any DB IO.
    settings = _make_settings("", None, port=0)
    monkeypatch.setattr(main_module, "get_settings", lambda: settings)
    monkeypatch.setattr(main_module, "configure_logging", lambda _s: None)

    assert main() == 2


# --------------------------------------------------------------------------- #
# serve() (two-plane DB mode) — Docker-gated via the shared migrated Postgres
# (api_db truncates every table, so the DB-sourced keyring starts EMPTY). Reuses
# the in-process serve pattern above: create_task(serve(...)) with signals off and
# an injected mock HTTP client, driven to shutdown by an injected event.
# --------------------------------------------------------------------------- #
def _serve_settings(
    *,
    kek_raw: str,
    dsn: str,
    bootstrap_path: str | None,
    dns_port: int,
    http_port: int,
) -> Settings:
    return Settings(
        credential_kek=SecretStr(kek_raw),
        database_dsn=SecretStr(dsn),
        admin_password_hash=SecretStr("PLACEHOLDER-argon2-hash"),
        session_secret=SecretStr("PLACEHOLDER-session-secret-0123456789"),
        bootstrap_path=bootstrap_path,
        dns_bind="127.0.0.1",
        dns_port=dns_port,
        http_bind="127.0.0.1",
        http_port=http_port,
    )


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


async def test_serve_without_bootstrap_file_reaches_ready_and_notauths(
    api_db: Database, pg_migrated: str
) -> None:
    # DB mode with ASTROPATH_BOOTSTRAP_PATH unset: no file is a valid boot (the M1
    # file requirement is file-mode only). The truncated DB means an EMPTY keyring,
    # yet readiness still reports the DNS plane loaded (empty-but-initialized), and
    # the data plane answers an unsigned UPDATE with NOTAUTH — zero keys configured
    # (SPEC §11 / T-M6-04). The listener binds ASTROPATH_DNS_BIND/PORT (no file to
    # carry a [listener]).
    kek_raw = generate_key()
    dns_port, http_port = _free_port(), _free_port()
    settings = _serve_settings(
        kek_raw=kek_raw,
        dsn=pg_migrated,
        bootstrap_path=None,
        dns_port=dns_port,
        http_port=http_port,
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


async def test_serve_with_bootstrap_file_still_seeds_keyring(
    api_db: Database, pg_migrated: str, keyring: Keyring, tmp_path: Path
) -> None:
    # DB mode WITH a bootstrap file: the file still seeds the keyring + routing and
    # supplies the listener bind/port (file mode unchanged). A signed UPDATE under
    # the file's TSIG key verifies and dispatches to the mocked HE provider →
    # NOERROR, proving the file seed survived the optional-file change.
    kek_raw = generate_key()
    dns_port, http_port = _free_port(), _free_port()
    path = tmp_path / "astropath.bootstrap.toml"
    _write_bootstrap(path, Kek([kek_raw]), port=dns_port)

    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, text="good")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    settings = _serve_settings(
        kek_raw=kek_raw,
        dsn=pg_migrated,
        bootstrap_path=str(path),
        dns_port=_free_port(),  # ignored in file mode: the file's [listener] wins
        http_port=http_port,
    )
    shutdown = asyncio.Event()
    serve_task = asyncio.create_task(
        serve(settings, shutdown=shutdown, install_signals=False, http_client=client)
    )
    try:
        await _await_bound(dns_port)
        await _await_bound(http_port)
        assert (await _await_ready(f"http://127.0.0.1:{http_port}"))["ready"] is True

        response = await asyncio.to_thread(
            dns.query.tcp, _signed_update(keyring), "127.0.0.1", 5.0, dns_port
        )
        assert response.rcode() == dns.rcode.NOERROR  # signed UPDATE dispatched
        assert response.had_tsig is True  # reply verified against the request MAC
        form = {k: v[0] for k, v in parse_qs(captured[0].content.decode()).items()}
        assert form["password"] == _HE_KEY  # per-record key seeded from the file
    finally:
        shutdown.set()

    assert await asyncio.wait_for(serve_task, timeout=10.0) == 0  # clean stop
    await client.aclose()
