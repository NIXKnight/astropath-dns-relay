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

"""Observability: data-plane metrics (SPEC §11.1, HIGH-1, HIGH-2, HIGH-8).

Prometheus counters/histograms/gauges are grouped on a :class:`DataPlaneMetrics`
instance bound to a :class:`~prometheus_client.CollectorRegistry`. ``main()``
builds one on the default registry; tests build one on a fresh registry to avoid
global bleed (SPEC §11.1). Metric samples never carry secret material — only
outcomes, reasons, and latencies.

M1 exposes metrics via :func:`start_metrics_server`
(``prometheus_client.start_http_server``) as an interim; this folds into a
FastAPI ``/metrics`` mount at M6 (T-M6-01). ``/healthz`` and per-plane
``/readyz`` (SPEC §11.2) also land with the management plane (M3+).
"""

from __future__ import annotations

import threading
from wsgiref.simple_server import WSGIServer

from prometheus_client import (
    REGISTRY,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    start_http_server,
)

__all__ = ["DataPlaneMetrics", "start_metrics_server"]

# TSIG failure reasons (SPEC §11.1 label domain).
TSIG_ABSENT = "absent"
TSIG_BADSIG = "badsig"
TSIG_BADKEY = "badkey"
TSIG_BADTIME = "badtime"
TSIG_UNKNOWNKEY = "unknownkey"

# Provider latency buckets (seconds) per SPEC §11.1.
_LATENCY_BUCKETS = (0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0)


class DataPlaneMetrics:
    """Prometheus metrics for the RFC2136 data plane (SPEC §11.1)."""

    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        reg = registry if registry is not None else REGISTRY

        # Counter base names omit the ``_total`` suffix (the client appends it).
        self.challenges = Counter(
            "astropath_challenges",
            "ACME challenge outcomes.",
            ["provider", "result", "action"],
            registry=reg,
        )
        self.tsig_failures = Counter(
            "astropath_tsig_failures",
            "Inbound TSIG verification failures by reason.",
            ["reason"],
            registry=reg,
        )
        self.tsig_badtime = Counter(
            "astropath_tsig_badtime",
            "BADTIME clock-skew TSIG failures (loud NTP signal).",
            registry=reg,
        )
        self.provider_call_duration = Histogram(
            "astropath_provider_call_duration_seconds",
            "Provider present/cleanup call latency.",
            ["provider"],
            buckets=_LATENCY_BUCKETS,
            registry=reg,
        )
        self.plane_restarts = Counter(
            "astropath_plane_restarts",
            "Per-plane supervisor restarts.",
            ["plane"],
            registry=reg,
        )
        self.plane_unhealthy = Gauge(
            "astropath_plane_unhealthy",
            "1 when a plane's restart budget is exhausted.",
            ["plane"],
            registry=reg,
        )
        self.zone_last_success = Gauge(
            "astropath_zone_last_success_timestamp",
            "Unix time of the last successful challenge per zone.",
            ["zone"],
            registry=reg,
        )

    # -- convenience recorders --------------------------------------------- #
    def record_tsig_failure(self, reason: str) -> None:
        """Increment the TSIG failure counter; BADTIME also bumps its own gauge."""
        self.tsig_failures.labels(reason=reason).inc()
        if reason == TSIG_BADTIME:
            self.tsig_badtime.inc()

    def record_challenge(self, provider: str, action: str, result: str) -> None:
        self.challenges.labels(provider=provider, result=result, action=action).inc()

    def record_plane_restart(self, plane: str) -> None:
        self.plane_restarts.labels(plane=plane).inc()

    def set_plane_unhealthy(self, plane: str, unhealthy: bool) -> None:
        self.plane_unhealthy.labels(plane=plane).set(1.0 if unhealthy else 0.0)

    def mark_zone_success(self, zone: str, timestamp: float) -> None:
        self.zone_last_success.labels(zone=zone).set(timestamp)


def start_metrics_server(
    port: int,
    addr: str = "0.0.0.0",
    registry: CollectorRegistry | None = None,
) -> tuple[WSGIServer, threading.Thread]:
    """Start the interim Prometheus HTTP exposition server (SPEC §11.1, M1).

    Returns the ``(WSGIServer, Thread)`` pair; call ``server.shutdown()`` to stop
    it during graceful shutdown.
    """
    return start_http_server(port, addr=addr, registry=registry or REGISTRY)
