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

"""Browser session: a signed — not encrypted — opaque admin marker (SPEC §8.2).

Starlette's :class:`~starlette.middleware.sessions.SessionMiddleware` signs the
cookie with an itsdangerous ``TimestampSigner`` but does **not** encrypt it — the
payload is client-readable base64 (``[C7]`` / proven in the session tests). So the
cookie carries **only** an opaque marker ``{"admin": true, "iat": <unix>}`` and
**never** a secret (no TSIG key, provider token, or password). Tampering breaks the
signature and the session is silently dropped.

Cookie flags are set explicitly against Starlette's permissive defaults
(``secure=False, httponly=False, samesite='lax'``): ``secure`` (HTTPS-only),
``httponly`` (no JS access), and ``samesite='strict'`` (no cross-site send).
``httponly`` is always applied by SessionMiddleware; the other two come from the
middleware options below. The signing secret is ``ASTROPATH_SESSION_SECRET``.
"""

from __future__ import annotations

import time

from fastapi import FastAPI, Request
from starlette.middleware.sessions import SessionMiddleware

from astropath.settings import Settings

__all__ = [
    "SESSION_COOKIE",
    "add_session_middleware",
    "clear_session",
    "mark_admin",
    "session_is_admin",
]

#: Cookie name (matches the ``APIKeyCookie`` extractor documented in require_admin).
SESSION_COOKIE = "session"

#: Session lifetime — a bounded window so a stolen cookie does not live forever.
SESSION_MAX_AGE = 12 * 60 * 60  # 12 hours


def add_session_middleware(app: FastAPI, settings: Settings) -> None:
    """Install signed-cookie sessions with the SPEC §8.2 flags.

    ``https_only=True`` sets the ``Secure`` flag (so the cookie needs HTTPS —
    behind nginx uvicorn's ``proxy_headers`` supply the https scheme, T-M3-08);
    ``same_site="strict"`` blocks cross-site sends. ``SessionMiddleware`` always
    marks the cookie ``HttpOnly``.
    """
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.session_secret.get_secret_value(),
        session_cookie=SESSION_COOKIE,
        max_age=SESSION_MAX_AGE,
        same_site="strict",
        https_only=True,
    )


def mark_admin(request: Request) -> None:
    """Record the opaque admin marker in the session (SPEC §8.2).

    Only ``admin`` + an issued-at timestamp — never a secret value.
    """
    request.session["admin"] = True
    request.session["iat"] = int(time.time())


def session_is_admin(request: Request) -> bool:
    """Whether the (signature-verified) session marks an authenticated admin."""
    return request.session.get("admin") is True


def clear_session(request: Request) -> None:
    """Drop the session marker (logout)."""
    request.session.clear()
