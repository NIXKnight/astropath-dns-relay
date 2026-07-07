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

"""Auth routes: session check, login, logout, password change (SPEC §9.1).

``GET /auth/session`` is the protected probe the SPA calls on load. ``POST
/auth/login`` verifies the admin password (argon2 offloaded, HIGH-11) and sets the
opaque session marker; ``POST /auth/logout`` clears it. The admin-password change
(``POST /auth/password``) and the ``AdminCredential`` persistence land in T-M3-05.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from astropath.api.auth import AuthService, get_auth, require_admin
from astropath.api.session import clear_session, mark_admin

__all__ = ["LoginRequest", "router"]

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class LoginRequest(BaseModel):
    """Admin login body (JSON, never a form — no multipart dependency)."""

    password: str = Field(min_length=1, repr=False)


@router.get(
    "/session",
    summary="Whether the caller is authenticated",
    dependencies=[Depends(require_admin)],
)
async def session_status() -> dict[str, bool]:
    # Reaching the handler means require_admin authorized the caller (cookie or
    # token); an unauthenticated caller got 401 from the dependency.
    return {"authenticated": True}


@router.post("/login", summary="Log in with the admin password")
async def login(
    payload: LoginRequest,
    request: Request,
    auth: AuthService = Depends(get_auth),
) -> dict[str, bool]:
    """Verify the admin password and set the session cookie (SPEC §8, §9.1).

    A wrong password returns 401 without distinguishing "no such admin" from
    "bad password" (there is a single admin). The password never appears in a
    log or an error body.
    """
    if not await auth.verify_admin_password(payload.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid credentials",
        )
    mark_admin(request)
    return {"authenticated": True}


@router.post("/logout", summary="Clear the session")
async def logout(request: Request) -> dict[str, bool]:
    """Drop the session marker (SPEC §9.1). Idempotent."""
    clear_session(request)
    return {"authenticated": False}
