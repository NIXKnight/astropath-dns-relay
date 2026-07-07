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

"""Admin-password persistence env -> UI (T-M3-05, SPEC §6.3, HIGH-5).

Against a real Postgres (Docker-gated): a password change writes AdminCredential
and the DB row becomes the source of truth across a simulated restart, with the
env hash demoted to first-boot fallback. A successful login against an outdated
stored hash transparently re-hashes to current params. Throwaway credentials.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from pydantic import SecretStr
from sqlmodel import select
from tests._api import api_client, login
from tests.test_api_app import make_settings

from astropath.api.app import create_app
from astropath.db import Database
from astropath.models import AdminCredential
from astropath.settings import Settings
from astropath.store import hash_password, password_needs_rehash

_INITIAL = "initial-throwaway-pw"
_CHANGED = "changed-throwaway-pw-1234"


def _settings() -> Settings:
    return make_settings(admin_password_hash=SecretStr(hash_password(_INITIAL)))


async def test_change_persists_and_env_becomes_fallback(api_db: Database) -> None:
    settings = _settings()
    async with api_client(create_app(settings=settings, database=api_db)) as c:
        assert (await login(c, _INITIAL)).status_code == 200  # env seed authorizes
        changed = await c.post(
            "/api/v1/auth/password",
            json={"current_password": _INITIAL, "new_password": _CHANGED},
        )
        assert changed.status_code == 200

    # Simulated restart: a fresh app + AuthService over the same database.
    async with api_client(create_app(settings=settings, database=api_db)) as c:
        assert (await login(c, _CHANGED)).status_code == 200  # DB row is truth now
        assert (await login(c, _INITIAL)).status_code == 401  # env demoted


async def test_change_requires_authentication(api_db: Database) -> None:
    async with api_client(create_app(settings=_settings(), database=api_db)) as c:
        response = await c.post(
            "/api/v1/auth/password",
            json={"current_password": _INITIAL, "new_password": _CHANGED},
        )
        assert response.status_code == 401  # require_admin gate, no session


async def test_wrong_current_password_is_403(api_db: Database) -> None:
    async with api_client(create_app(settings=_settings(), database=api_db)) as c:
        await login(c, _INITIAL)
        response = await c.post(
            "/api/v1/auth/password",
            json={"current_password": "not-current", "new_password": _CHANGED},
        )
        assert response.status_code == 403


async def test_login_rehashes_an_outdated_stored_hash(api_db: Database) -> None:
    # Seed AdminCredential with a deliberately weak-param hash.
    weak = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash(_INITIAL)
    assert password_needs_rehash(weak) is True
    async with api_db.session() as session:
        session.add(AdminCredential(id=1, password_hash=weak))
        await session.commit()

    async with api_client(create_app(settings=_settings(), database=api_db)) as c:
        assert (await login(c, _INITIAL)).status_code == 200

    async with api_db.session() as session:
        row = (await session.execute(select(AdminCredential))).scalars().one()
    assert row.password_hash != weak  # re-hashed on successful verify
    assert password_needs_rehash(row.password_hash) is False
