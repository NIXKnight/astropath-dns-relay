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

"""Process entrypoint and singular resource ownership (SPEC §2, T-M1-24).

``main()`` owns the single asyncio process and is the **sole** owner of shared
resource startup/teardown (HTTP client, keyring, routing, metrics, DNS sockets)
— nothing is created in a ``FastAPI(lifespan=...)`` hook (MED-1). Planes run
under *independent* per-plane supervisors (:func:`astropath.supervisor.supervise`)
— deliberately not ``asyncio.gather`` (orphans a healthy sibling on crash) and
not a top-level ``TaskGroup`` (cancels a healthy sibling) — per SPEC §2.1 /
HIGH-1. A shared :class:`asyncio.Event` coordinates graceful shutdown: SIGTERM
and SIGINT set it, both planes wind down, and resources are disposed exactly once.

M1 runs only the data plane (RFC2136/TSIG listener). The management plane
(supervisor B) is added at M3: it embeds the FastAPI app under
``uvicorn.Server(uvicorn.Config(app, log_config=None, proxy_headers=True,
forwarded_allow_ips=settings.forwarded_allow_ips, lifespan="off"))`` with
``server.install_signal_handlers`` neutralized (this module owns signals) and
``server.should_exit`` driven by the same ``shutdown`` event. That seam slots in
here without changing ownership; M1 deliberately does not import uvicorn.
"""

from __future__ import annotations

import asyncio
import logging
import signal

import httpx
from prometheus_client import CollectorRegistry

from astropath.bootstrap import build_data_plane
from astropath.data_plane.dispatcher import Dispatcher
from astropath.data_plane.server import Rfc2136Server
from astropath.logging_config import configure_logging
from astropath.observability import DataPlaneMetrics, start_metrics_server
from astropath.providers._http import build_async_client
from astropath.settings import Settings, get_settings
from astropath.startup import StartupError, validate_and_load
from astropath.supervisor import RestartLimiter, supervise

__all__ = ["main", "run"]

log = logging.getLogger("astropath.main")


def _install_signal_handlers(shutdown: asyncio.Event) -> None:
    """Route SIGTERM/SIGINT to the shared ``shutdown`` event (SPEC §2.1)."""
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, shutdown.set)
        except NotImplementedError:  # pragma: no cover — non-Unix event loop
            signal.signal(sig, lambda *_: shutdown.set())


async def run(
    settings: Settings,
    *,
    shutdown: asyncio.Event | None = None,
    install_signals: bool = True,
    http_client: httpx.AsyncClient | None = None,
) -> int:
    """Run the M1 data plane until shutdown; return the process exit code.

    ``main()`` owns every shared resource created here and disposes it exactly
    once on the way out. Returns ``0`` for a clean, shutdown-driven stop and
    ``1`` when the data plane exhausts its restart budget (surface unhealthy so
    the orchestrator restarts the whole process). Startup validation failures
    propagate as :class:`~astropath.startup.StartupError` before any resource is
    allocated. Tests inject ``shutdown``/``http_client`` and disable signals;
    an injected client is owned by the caller and is not closed here.
    """
    kek, config = validate_and_load(
        settings.credential_kek.get_secret_value(), settings.bootstrap_path
    )
    shutdown = shutdown if shutdown is not None else asyncio.Event()

    owns_client = http_client is None
    client = http_client if http_client is not None else build_async_client()
    registry = CollectorRegistry()
    metrics = DataPlaneMetrics(registry=registry)
    metrics_server, _thread = start_metrics_server(
        settings.metrics_port, registry=registry
    )

    server: Rfc2136Server | None = None
    try:
        runtime = build_data_plane(config, http_client=client)
        dispatcher = Dispatcher(runtime.routing, metrics)
        server = Rfc2136Server(
            runtime.keyring,
            dispatcher,
            metrics,
            host=config.listener_host,
            port=config.listener_port,
        )
        if install_signals:
            _install_signal_handlers(shutdown)

        # Supervisor A — the data plane. Supervisor B (management/uvicorn) joins
        # at M3 as a second, independent supervise() task sharing this shutdown.
        dns_task = asyncio.create_task(
            supervise("dns", server.serve, shutdown, RestartLimiter(), metrics),
            name="plane-dns",
        )
        shutdown_wait = asyncio.create_task(shutdown.wait(), name="shutdown-wait")

        log.info(
            "data plane serving",
            extra={"host": config.listener_host, "port": server.port},
        )
        await asyncio.wait(
            {dns_task, shutdown_wait}, return_when=asyncio.FIRST_COMPLETED
        )
        # If the plane task finished first it gave up (serve_forever only ends
        # via cancellation); otherwise shutdown was requested and we cancel it.
        plane_gave_up = dns_task.done()

        for task in (dns_task, shutdown_wait):
            if not task.done():
                task.cancel()
        await asyncio.gather(dns_task, shutdown_wait, return_exceptions=True)

        if plane_gave_up:
            log.error("data plane exhausted its restart budget; exiting unhealthy")
            return 1
        log.info("graceful shutdown complete")
        return 0
    finally:
        if server is not None:
            server.close()
        if owns_client:
            await client.aclose()
        metrics_server.shutdown()


def main() -> int:
    """``python -m astropath.main`` / console-script entrypoint (SPEC §2)."""
    settings = get_settings()
    configure_logging(settings)
    try:
        return asyncio.run(run(settings))
    except StartupError:
        log.exception("startup validation failed; refusing to bind")
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
