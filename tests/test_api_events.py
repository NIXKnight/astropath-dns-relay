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

"""Audit-events endpoint (T-M3-13, SPEC §9.1, HIGH-8).

Against real Postgres (Docker-gated): the append-only ChallengeEvent log is
queryable read-only via the API, newest-first, with limit/offset pagination and a
total count. The rows carry no secrets. Read-only — there is no POST/DELETE.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest_asyncio
from tests._api import api_client, seed_api_token
from tests.test_api_app import make_settings

from astropath.api.app import create_app
from astropath.db import Database
from astropath.models import ChallengeEvent

_READ_FIELDS = {
    "id",
    "ts",
    "zone",
    "record_name",
    "action",
    "provider",
    "result",
    "latency_ms",
    "tsig_key_id",
    "source",
    "error_detail",
}


@pytest_asyncio.fixture
async def client(api_db: Database) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(settings=make_settings(), database=api_db)
    headers = await seed_api_token(api_db)
    async with api_client(app) as c:
        c.headers.update(headers)
        yield c


async def _seed_event(
    database: Database, *, zone: str, error_detail: str | None = None
) -> None:
    async with database.session() as session:
        session.add(
            ChallengeEvent(
                zone=zone,
                record_name=f"_acme-challenge.{zone}",
                action="present",
                provider="hurricane",
                result="ok",
                latency_ms=12,
                tsig_key_id=None,
                source="10.0.0.5",
                error_detail=error_detail,
            )
        )
        await session.commit()


async def test_empty_log_returns_zero_total(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/events")
    assert response.status_code == 200
    body = response.json()
    assert body == {"items": [], "total": 0, "limit": 50, "offset": 0}


async def test_events_are_queryable_newest_first(
    client: httpx.AsyncClient, api_db: Database
) -> None:
    for i in range(3):
        await _seed_event(api_db, zone=f"z{i}.example.")

    body = (await client.get("/api/v1/events")).json()
    assert body["total"] == 3
    zones = [item["zone"] for item in body["items"]]
    assert zones == ["z2.example.", "z1.example.", "z0.example."]  # newest first


async def test_rows_expose_no_secret_fields(
    client: httpx.AsyncClient, api_db: Database
) -> None:
    await _seed_event(api_db, zone="audit.example.", error_detail="redacted detail")
    item = (await client.get("/api/v1/events")).json()["items"][0]
    # Exact field set is the primary guard: no accidental secret column leaks.
    assert set(item) == _READ_FIELDS
    for forbidden in ("secret", "password", "hash"):
        assert not any(forbidden in name for name in item)


async def test_pagination_limit_and_offset(
    client: httpx.AsyncClient, api_db: Database
) -> None:
    for i in range(5):
        await _seed_event(api_db, zone=f"z{i}.example.")

    first = (await client.get("/api/v1/events?limit=2&offset=0")).json()
    assert first["total"] == 5
    assert [i["zone"] for i in first["items"]] == ["z4.example.", "z3.example."]

    second = (await client.get("/api/v1/events?limit=2&offset=2")).json()
    assert [i["zone"] for i in second["items"]] == ["z2.example.", "z1.example."]

    last = (await client.get("/api/v1/events?limit=2&offset=4")).json()
    assert [i["zone"] for i in last["items"]] == ["z0.example."]


async def test_limit_bounds_are_enforced(client: httpx.AsyncClient) -> None:
    assert (await client.get("/api/v1/events?limit=0")).status_code == 422
    assert (await client.get("/api/v1/events?limit=201")).status_code == 422
    assert (await client.get("/api/v1/events?offset=-1")).status_code == 422


async def test_events_endpoint_is_read_only(client: httpx.AsyncClient) -> None:
    # The audit log is dispatcher-owned: the collection path serves GET only, so
    # any mutating method is 405 (method not allowed on an existing route).
    assert (await client.post("/api/v1/events", json={})).status_code == 405
    assert (await client.delete("/api/v1/events")).status_code == 405
    assert (await client.put("/api/v1/events", json={})).status_code == 405


async def test_requires_authentication(api_db: Database) -> None:
    app = create_app(settings=make_settings(), database=api_db)
    async with api_client(app) as c:
        assert (await c.get("/api/v1/events")).status_code == 401
