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

"""Process entrypoint and singular resource ownership (SPEC §2, T-M1-24, T-M3-01).

``main()`` owns the single asyncio process and is the **sole** owner of shared
resource startup/teardown (HTTP client, keyring, routing, metrics, DNS sockets,
database engine) — nothing is created in a ``FastAPI(lifespan=...)`` hook
(MED-1). Planes run under *independent* per-plane supervisors
(:func:`astropath.supervisor.supervise`) — deliberately not ``asyncio.gather``
(orphans a healthy sibling on crash) and not a top-level ``TaskGroup`` (cancels a
healthy sibling) — per SPEC §2.1 / HIGH-1. A shared :class:`asyncio.Event`
coordinates graceful shutdown: SIGTERM and SIGINT set it, both planes wind down,
and resources are disposed exactly once.

:func:`serve` is the production composition. Supervisor A is the RFC2136 data
plane; **supervisor B** embeds the FastAPI management app under
``uvicorn.Server(uvicorn.Config(app, log_config=None, proxy_headers=True,
forwarded_allow_ips=..., lifespan="off"))``. uvicorn's own signal capture is
neutralized (this module owns SIGTERM/SIGINT) and its graceful stop is driven by
``server.should_exit`` off the same ``shutdown`` event. A single DB-backed
:class:`~astropath.cache.RoutingCache` is the **sole** source of routing + live
keyring: the management API refreshes it on writes (T-M3-16) and the data plane
reads it, so a TSIG key or domain added in the panel converges without a restart.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
from collections.abc import Awaitable, Callable, Generator

import httpx
import uvicorn
from fastapi import FastAPI
from prometheus_client import CollectorRegistry

from astropath.api.app import create_app
from astropath.audit import DbAuditSink
from astropath.cache import RoutingCache, make_db_loader
from astropath.data_plane.dispatcher import Dispatcher
from astropath.data_plane.server import Rfc2136Server
from astropath.db import Database
from astropath.logging_config import configure_logging
from astropath.observability import DataPlaneMetrics
from astropath.providers._http import build_async_client
from astropath.settings import Settings, get_settings
from astropath.startup import StartupError, validate_db_startup, validate_kek
from astropath.supervisor import RestartLimiter, supervise

__all__ = ["build_management_server", "main", "serve"]

log = logging.getLogger("astropath.main")


def _install_signal_handlers(shutdown: asyncio.Event) -> None:
    """Route SIGTERM/SIGINT to the shared ``shutdown`` event (SPEC §2.1)."""
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, shutdown.set)
        except NotImplementedError:  # pragma: no cover — non-Unix event loop
            signal.signal(sig, lambda *_: shutdown.set())


@contextlib.contextmanager
def _no_signal_capture() -> Generator[None, None, None]:
    """A no-op stand-in for ``uvicorn.Server.capture_signals`` (SPEC §2.2).

    uvicorn 0.50 installs its SIGTERM/SIGINT handlers inside a
    ``capture_signals()`` context manager entered by ``Server.serve()`` (the
    method the older SPEC text called ``install_signal_handlers``). Overriding it
    with this no-op leaves ``main()`` the single owner of coordinated shutdown;
    graceful stop is driven by ``server.should_exit``.
    """
    yield


def build_management_server(app: FastAPI, settings: Settings) -> uvicorn.Server:
    """Build the embedded uvicorn server for the management plane (SPEC §2.2).

    ``lifespan="off"`` makes ``main()`` the single owner of startup/teardown
    (MED-1); ``proxy_headers`` + ``forwarded_allow_ips`` (T-M3-08) restore the
    real client IP/scheme behind nginx; ``log_config=None`` yields to our
    dictConfig. uvicorn's signal capture is neutralized so this module owns
    SIGTERM/SIGINT.
    """
    config = uvicorn.Config(
        app,
        host=settings.http_bind,
        port=settings.http_port,
        log_config=None,
        proxy_headers=True,
        forwarded_allow_ips=settings.forwarded_allow_ips,
        lifespan="off",
    )
    server = uvicorn.Server(config)
    server.capture_signals = _no_signal_capture  # type: ignore[method-assign]
    return server


def _management_factory(
    server: uvicorn.Server, shutdown: asyncio.Event
) -> Callable[[], Awaitable[None]]:
    """A supervise()-compatible factory serving uvicorn until shutdown.

    Runs ``server.serve()`` and, on the shared ``shutdown`` event, sets
    ``should_exit`` for a graceful uvicorn stop and awaits the serve task. A crash
    inside uvicorn propagates so the supervisor can restart the plane.
    """

    async def _factory() -> None:
        serve_task = asyncio.create_task(server.serve(), name="uvicorn-serve")
        stop_wait = asyncio.create_task(shutdown.wait(), name="uvicorn-stop-wait")
        try:
            await asyncio.wait(
                {serve_task, stop_wait}, return_when=asyncio.FIRST_COMPLETED
            )
            if not serve_task.done():
                server.should_exit = True
                await serve_task
            else:
                serve_task.result()  # re-raise a uvicorn failure to the supervisor
        finally:
            if not stop_wait.done():
                stop_wait.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await stop_wait

    return _factory


async def _safe_initial_refresh(cache: RoutingCache) -> None:
    """Best-effort startup cache load (SPEC §6.4): a DB blip must not crash.

    On failure DNS readiness stays false (the cache is empty) but the process does
    not crash — it retries as the management API writes converge, or on the next
    boot once the database is reachable.
    """
    try:
        await cache.refresh()
    except Exception:  # noqa: BLE001 - degraded start is intentional (SPEC §6.4)
        log.warning(
            "initial routing cache refresh failed; DNS readiness stays false until "
            "the database is reachable"
        )


async def serve(
    settings: Settings,
    *,
    shutdown: asyncio.Event | None = None,
    install_signals: bool = True,
    http_client: httpx.AsyncClient | None = None,
) -> int:
    """Run both planes (data + management) until shutdown; return the exit code.

    Supervisor A is the RFC2136 data plane, driven live by the shared DB cache;
    supervisor B embeds the FastAPI app under uvicorn. The database is the sole
    backend (SPEC §16): the DB-backed :class:`~astropath.cache.RoutingCache` is the
    only source of the keyring + routing, and the listener binds
    ``ASTROPATH_DNS_BIND`` / ``ASTROPATH_DNS_PORT``. Both planes share one
    ``shutdown`` event. Returns ``0`` on a clean stop and ``1`` when either plane
    exhausts its restart budget. Startup validation failures (a malformed KEK, an
    unreachable/stale DB) raise :class:`~astropath.startup.StartupError` before
    resources are allocated (preserving the ``main()`` return-2 contract).
    """
    kek = validate_kek(settings.credential_kek.get_secret_value())
    shutdown = shutdown if shutdown is not None else asyncio.Event()

    owns_client = http_client is None
    client = http_client if http_client is not None else build_async_client()
    # Metrics are exposed by the FastAPI app's /metrics route (T-M3-14), which
    # serves this exact registry.
    registry = CollectorRegistry()
    metrics = DataPlaneMetrics(registry=registry)

    database = Database.from_dsn(settings.database_dsn.get_secret_value())
    cache = RoutingCache(make_db_loader(database.sessionmaker, kek, client))

    dns_server: Rfc2136Server | None = None
    dns_task: asyncio.Task[None] | None = None
    try:
        # Fail-fast the DB-backed preconditions before binding readiness (T-M6-10):
        # DB reachable, schema at head, every provider/algorithm valid, SPA dir
        # present. A failure raises StartupError; the finally disposes the DB
        # engine + client and main() returns 2.
        await validate_db_startup(database, settings)
        await _safe_initial_refresh(cache)
        dispatcher = Dispatcher(
            cache,  # the RoutingCache is the sole RoutingSource
            metrics,
            audit=DbAuditSink(database.sessionmaker),
            tsig_key_resolver=cache.tsig_key_id_for,
        )
        dns_server = Rfc2136Server(
            lambda: cache.keyring,  # live keyring; API-added keys converge here
            dispatcher,
            metrics,
            host=settings.dns_bind,
            port=settings.dns_port,
        )
        # Capture the non-optional instance so the readiness closure type-checks.
        readiness_server = dns_server

        def _dns_ready() -> bool:
            # DNS readiness (SPEC §11.2, T-M6-04): both sockets bound AND the DB
            # routing snapshot loaded. An empty-but-initialized keyring is "loaded"
            # — zero configured keys is valid (unknown/unsigned UPDATEs answer
            # NOTAUTH). cache.is_populated is the keyring+routing gate.
            return readiness_server.is_accepting and cache.is_populated

        app = create_app(
            settings=settings,
            database=database,
            cache=cache,
            kek=kek,
            metrics_registry=registry,
            dns_ready=_dns_ready,
        )
        api_server = build_management_server(app, settings)
        if install_signals:
            _install_signal_handlers(shutdown)

        dns_task = asyncio.create_task(
            supervise("dns", dns_server.serve, shutdown, RestartLimiter(), metrics),
            name="plane-dns",
        )
        api_task = asyncio.create_task(
            supervise(
                "api",
                _management_factory(api_server, shutdown),
                shutdown,
                RestartLimiter(),
                metrics,
            ),
            name="plane-api",
        )
        shutdown_wait = asyncio.create_task(shutdown.wait(), name="shutdown-wait")

        log.info(
            "both planes serving",
            extra={
                "dns_host": settings.dns_bind,
                "dns_port": dns_server.port,
                "http_host": settings.http_bind,
                "http_port": settings.http_port,
            },
        )
        await asyncio.wait(
            {dns_task, api_task, shutdown_wait}, return_when=asyncio.FIRST_COMPLETED
        )
        # A plane task completing before shutdown_wait means its supervisor gave
        # up (both plane factories otherwise run until the shared shutdown).
        plane_gave_up = dns_task.done() or api_task.done()

        # Graceful drain order (SPEC §2/§3, T-M6-05): stop accepting new work on
        # both planes, drain in-flight DNS dispatches (bounded), then wind down
        # the API supervisor — uvicorn returns once it honors should_exit.
        dns_server.stop_accepting()
        api_server.should_exit = True
        await dns_server.drain(settings.shutdown_drain_timeout)

        for task in (api_task, shutdown_wait):
            if not task.done():
                task.cancel()
        await asyncio.gather(api_task, shutdown_wait, return_exceptions=True)

        if plane_gave_up:
            log.error("a plane exhausted its restart budget; exiting unhealthy")
            return 1
        log.info("graceful shutdown complete")
        return 0
    finally:
        # Resource disposal order (SPEC §2/§3): DB pool, then HTTP clients, then
        # the DNS sockets last — in-flight replies were already drained above.
        await database.dispose()
        if owns_client:
            await client.aclose()
        if dns_task is not None and not dns_task.done():
            dns_task.cancel()
            await asyncio.gather(dns_task, return_exceptions=True)
        if dns_server is not None:
            dns_server.close()


def main() -> int:
    """``python -m astropath.main`` / console-script entrypoint (SPEC §2)."""
    settings = get_settings()
    configure_logging(settings)
    try:
        return asyncio.run(serve(settings))
    except StartupError:
        log.exception("startup validation failed; refusing to bind")
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
