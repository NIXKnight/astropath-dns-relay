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

"""Management-API test helpers (not collected — leading underscore).

An in-process ``httpx`` client over ``ASGITransport`` (no uvicorn) with an https
base URL so Secure session cookies round-trip, plus a login shortcut. Shared by
the T-M3-05/09/10/11/12/13/16 suites.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI

from astropath.db import Database
from astropath.store import build_api_token


@asynccontextmanager
async def api_client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    """Yield an httpx client bound to ``app`` over an https ASGI transport."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="https://astropath.test"
    ) as client:
        yield client


async def login(client: httpx.AsyncClient, password: str) -> httpx.Response:
    """POST the admin password to establish the session cookie."""
    return await client.post("/api/v1/auth/login", json={"password": password})


async def seed_api_token(
    database: Database, *, name: str = "test-token"
) -> dict[str, str]:
    """Insert an ApiToken row and return an ``X-API-Key`` header for CRUD auth.

    Token auth is CSRF-exempt, so CRUD suites avoid the cookie/origin dance.
    """
    row, token = build_api_token(name=name)
    async with database.session() as session:
        session.add(row)
        await session.commit()
    return {"X-API-Key": token}
