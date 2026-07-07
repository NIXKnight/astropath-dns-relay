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

T-M3-02 lands the protected ``GET /auth/session`` probe (the SPA calls it on load
to learn whether the current cookie/token still authorizes). Login/logout and the
admin-password change land in T-M3-04 / T-M3-05.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from astropath.api.auth import require_admin

__all__ = ["router"]

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.get(
    "/session",
    summary="Whether the caller is authenticated",
    dependencies=[Depends(require_admin)],
)
async def session_status() -> dict[str, bool]:
    # Reaching the handler means require_admin authorized the caller (cookie or
    # token); an unauthenticated caller got 401 from the dependency.
    return {"authenticated": True}
