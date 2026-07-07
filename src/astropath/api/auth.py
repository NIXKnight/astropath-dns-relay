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

"""Management-plane authentication (SPEC §8, HIGH-5).

:func:`require_admin` authorizes a request via **either** a signed session cookie
**or** an ``X-API-Key`` header. Both extractors use ``auto_error=False`` (``[C7]``)
so the first missing credential does not short-circuit before the alternate is
tried; when neither is valid the dependency raises ``HTTPException(401)`` itself.
Missing-credential status is **401** on FastAPI ≥ 0.122.0 (pinned).

:class:`AuthService` resolves the two non-cookie credentials against storage: an
API token (SHA-256 hash, constant-time; SPEC §6.2) and — from T-M3-04 — the admin
password (argon2id, offloaded via ``asyncio.to_thread``, SPEC §7.4/HIGH-11). It is
built by ``create_app`` from ``main()``-owned resources and read off ``app.state``,
so tests can substitute a fake without a live database.

Secret discipline: neither the token nor the password is ever logged; only the
opaque session marker and hashes are handled here.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import HTTPException, Request, Security, status
from fastapi.security import APIKeyCookie, APIKeyHeader
from sqlmodel import select

from astropath.api.session import SESSION_COOKIE, session_is_admin
from astropath.db import Database
from astropath.models import ApiToken
from astropath.settings import Settings
from astropath.store import hash_token

__all__ = ["AuthService", "get_auth", "require_admin"]


class AuthService:
    """Resolves API-token and admin-password credentials against storage.

    Holds the ``main()``-owned :class:`~astropath.db.Database` (or ``None`` for a
    DB-less unit context) and process :class:`~astropath.settings.Settings`. Admin
    password verification lands in T-M3-04; T-M3-02 provides token validation.
    """

    __slots__ = ("_database", "_settings")

    def __init__(self, database: Database | None, settings: Settings) -> None:
        self._database = database
        self._settings = settings

    async def api_token_valid(self, api_key: str) -> bool:
        """Return ``True`` iff ``api_key`` matches a stored token (SPEC §6.2).

        The presented token is SHA-256 hashed and matched against the indexed
        ``token_hash`` column — the stored form is one-way, and matching on the
        digest of a 256-bit random token is not timing-sensitive to the secret.
        On a hit the token's ``last_used_at`` is stamped. Returns ``False`` when
        no database is configured or the token is unknown.
        """
        if self._database is None:
            return False
        digest = hash_token(api_key)
        async with self._database.session() as session:
            row = (
                await session.execute(
                    select(ApiToken).where(ApiToken.token_hash == digest)
                )
            ).scalar_one_or_none()
            if row is None:
                return False
            row.last_used_at = datetime.now(UTC)
            await session.commit()
            return True


def get_auth(request: Request) -> AuthService:
    """Injected :class:`AuthService` (set on ``app.state`` by create_app)."""
    auth: AuthService = request.app.state.astropath.auth
    return auth


# Read-only credential extractors (they create nothing; SPEC §8.3). auto_error is
# False on BOTH so a missing cookie does not short-circuit the header check.
_session_scheme = APIKeyCookie(name=SESSION_COOKIE, auto_error=False)
_api_key_scheme = APIKeyHeader(name="X-API-Key", auto_error=False)


async def require_admin(
    request: Request,
    session_cookie: str | None = Security(_session_scheme),
    api_key: str | None = Security(_api_key_scheme),
) -> None:
    """Authorize via signed session cookie OR ``X-API-Key``; else 401 (SPEC §8.3).

    The cookie path trusts the SessionMiddleware-verified opaque marker; the
    header path validates the token against storage. Both-absent / both-invalid
    raises 401 here (FastAPI ≥ 0.122.0 missing-credential semantics).
    """
    if session_cookie is not None and session_is_admin(request):
        return
    if api_key is not None and await get_auth(request).api_token_valid(api_key):
        return
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="authentication required",
    )
