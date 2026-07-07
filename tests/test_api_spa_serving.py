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

"""SPA deep-link catch-all serving (T-TEST-17, T-M4-04, SPEC §9.3, MED-5).

Uses the FastAPI ``TestClient`` against a tiny fixture ``dist/`` (index.html +
assets/) injected via ``create_app(static_dir=...)`` — no built frontend needed.
Proves the explicit catch-all resolves deep links to ``index.html`` while API and
ops routes stay authoritative: an unknown ``/api/v1/*`` is 404 JSON, hashed assets
carry the right content type, and ``/healthz`` / ``/readyz`` / ``/metrics`` /
``/openapi.json`` / ``/docs`` are never masked by the SPA shell. Also proves the
app boots when the dist is absent (fallback disabled with a log line).
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from tests.test_api_app import make_settings

from astropath.api import app as app_module
from astropath.api.app import create_app

_INDEX_HTML = (
    "<!doctype html><html><head><title>Astropath Admin</title></head>"
    '<body><div id="root"></div><!-- SPA_FIXTURE_MARKER --></body></html>'
)


@pytest.fixture
def dist(tmp_path: Path) -> Path:
    """A minimal built-SPA layout: index.html + a hashed asset + a public file."""
    root = tmp_path / "dist"
    (root / "assets").mkdir(parents=True)
    (root / "index.html").write_text(_INDEX_HTML, encoding="utf-8")
    (root / "assets" / "index-abc123.js").write_text(
        "console.log('astropath');", encoding="utf-8"
    )
    (root / "favicon.svg").write_text(
        '<svg xmlns="http://www.w3.org/2000/svg"></svg>', encoding="utf-8"
    )
    return root


@pytest.fixture
def client(dist: Path) -> Iterator[TestClient]:
    app = create_app(settings=make_settings(), static_dir=dist)
    with TestClient(app) as test_client:
        yield test_client


# --------------------------------------------------------------------------- #
# Deep links resolve to the SPA shell.
# --------------------------------------------------------------------------- #
def test_deep_link_returns_index_html(client: TestClient) -> None:
    response = client.get("/backends/5")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "SPA_FIXTURE_MARKER" in response.text


def test_root_returns_index_html(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "SPA_FIXTURE_MARKER" in response.text


def test_nested_deep_link_returns_index_html(client: TestClient) -> None:
    # A multi-segment non-API path is still the SPA (client-side router owns it).
    response = client.get("/tsig-keys/create/anything")
    assert response.status_code == 200
    assert "SPA_FIXTURE_MARKER" in response.text


# --------------------------------------------------------------------------- #
# Static assets are served with the correct content type, not the shell.
# --------------------------------------------------------------------------- #
def test_hashed_asset_served_with_type(client: TestClient) -> None:
    response = client.get("/assets/index-abc123.js")
    assert response.status_code == 200
    assert "javascript" in response.headers["content-type"]
    assert "SPA_FIXTURE_MARKER" not in response.text


def test_public_file_served_with_type(client: TestClient) -> None:
    response = client.get("/favicon.svg")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("image/svg+xml")


def test_missing_asset_is_404_not_index(client: TestClient) -> None:
    # Under the /assets mount a missing file is a real 404, never the SPA shell.
    response = client.get("/assets/does-not-exist.js")
    assert response.status_code == 404
    assert "SPA_FIXTURE_MARKER" not in response.text


# --------------------------------------------------------------------------- #
# API + ops routes are never shadowed by the catch-all.
# --------------------------------------------------------------------------- #
def test_unknown_api_path_is_404_json(client: TestClient) -> None:
    response = client.get("/api/v1/nonexistent")
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/json")
    assert response.json()["detail"] == "Not Found"


def test_real_api_route_not_shadowed(client: TestClient) -> None:
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_probes_not_shadowed(client: TestClient) -> None:
    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").status_code in (200, 503)
    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    assert metrics.headers["content-type"].startswith("text/plain")


def test_docs_and_schema_stay_auth_gated_not_spa(client: TestClient) -> None:
    # 401 (require_admin), not 200 index.html — the catch-all must not swallow
    # the auth-gated docs/schema routes registered before it.
    for path in ("/openapi.json", "/docs", "/redoc"):
        response = client.get(path)
        assert response.status_code == 401, path
        assert "SPA_FIXTURE_MARKER" not in response.text


# --------------------------------------------------------------------------- #
# The app boots even when no built SPA is present (fallback disabled + log line).
# --------------------------------------------------------------------------- #
def test_app_boots_without_dist(tmp_path: Path) -> None:
    missing = tmp_path / "no-such-dist"
    # Spy on the module logger to assert the fallback log line deterministically:
    # the suite's configure_logging() reconfigures global logging, so handler- or
    # caplog-based capture would be test-order-dependent here.
    with patch.object(app_module.log, "warning") as mock_warning:
        app = create_app(settings=make_settings(), static_dir=missing)

    with TestClient(app) as test_client:
        # No catch-all registered: a deep link is a plain 404, ops still serve.
        assert test_client.get("/backends/5").status_code == 404
        assert test_client.get("/healthz").status_code == 200

    mock_warning.assert_called_once()
    assert "serving API only" in mock_warning.call_args.args[0]
