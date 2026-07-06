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

"""Data-plane metrics tests (T-M1-27, SPEC §11.1)."""

from __future__ import annotations

from prometheus_client import CollectorRegistry, generate_latest

from astropath.observability import DataPlaneMetrics


def test_badtime_increments_dedicated_and_reason_counters() -> None:
    reg = CollectorRegistry()
    metrics = DataPlaneMetrics(registry=reg)

    metrics.record_tsig_failure("badtime")

    assert reg.get_sample_value("astropath_tsig_badtime_total") == 1.0
    assert (
        reg.get_sample_value("astropath_tsig_failures_total", {"reason": "badtime"})
        == 1.0
    )


def test_non_badtime_failure_does_not_touch_badtime_counter() -> None:
    reg = CollectorRegistry()
    metrics = DataPlaneMetrics(registry=reg)

    metrics.record_tsig_failure("badsig")

    assert (
        reg.get_sample_value("astropath_tsig_failures_total", {"reason": "badsig"})
        == 1.0
    )
    # badtime counter exists but stays 0 (never observed).
    assert reg.get_sample_value("astropath_tsig_badtime_total") == 0.0


def test_challenge_and_zone_success_and_plane_metrics() -> None:
    reg = CollectorRegistry()
    metrics = DataPlaneMetrics(registry=reg)

    metrics.record_challenge(provider="hurricane", action="present", result="ok")
    metrics.mark_zone_success("example.com", 1_700_000_000.0)
    metrics.record_plane_restart("dns")
    metrics.set_plane_unhealthy("dns", True)

    assert (
        reg.get_sample_value(
            "astropath_challenges_total",
            {"provider": "hurricane", "action": "present", "result": "ok"},
        )
        == 1.0
    )
    assert (
        reg.get_sample_value(
            "astropath_zone_last_success_timestamp", {"zone": "example.com"}
        )
        == 1_700_000_000.0
    )
    assert (
        reg.get_sample_value("astropath_plane_restarts_total", {"plane": "dns"}) == 1.0
    )
    assert reg.get_sample_value("astropath_plane_unhealthy", {"plane": "dns"}) == 1.0


def test_metrics_are_scrapeable() -> None:
    reg = CollectorRegistry()
    metrics = DataPlaneMetrics(registry=reg)
    metrics.record_challenge(provider="hurricane", action="cleanup", result="ok")

    scrape = generate_latest(reg).decode()
    assert "astropath_challenges_total" in scrape
    assert "astropath_provider_call_duration_seconds" in scrape
