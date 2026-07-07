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

"""API-token routes (SPEC §9.1, §6.2, §8.1, LOW-1).

``POST /api/v1/tokens`` mints a high-entropy token server-side and returns it in
plaintext **exactly once**; only its SHA-256 hash is persisted (:func:`build_api_token`),
so a stored token is never recoverable and auth matches on the hash in constant time
(store layer). ``GET`` lists labels and usage timestamps only — never the token or its
hash. ``DELETE`` revokes. A lost token is revoked and a fresh one minted, never
redisplayed.
"""

from __future__ import annotations

from collections.abc import Sequence

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from astropath.api.auth import require_admin
from astropath.api.deps import get_session
from astropath.api.schemas import (
    ONE_TIME_SECRET_NOTICE,
    ApiTokenCreate,
    ApiTokenCreated,
    ApiTokenRead,
)
from astropath.models import ApiToken
from astropath.store import build_api_token

__all__ = ["router"]

router = APIRouter(
    prefix="/api/v1/tokens",
    tags=["tokens"],
    dependencies=[Depends(require_admin)],
)


@router.post(
    "",
    response_model=ApiTokenCreated,
    status_code=status.HTTP_201_CREATED,
    response_description=ONE_TIME_SECRET_NOTICE,
)
async def create_api_token(
    payload: ApiTokenCreate,
    session: AsyncSession = Depends(get_session),
) -> ApiTokenCreated:
    row, plaintext = build_api_token(name=payload.name)  # plaintext revealed once
    session.add(row)
    await session.commit()
    await session.refresh(row)
    assert row.id is not None
    return ApiTokenCreated(
        id=row.id,
        name=row.name,
        created_at=row.created_at,
        last_used_at=row.last_used_at,
        token=plaintext,
    )


@router.get("", response_model=list[ApiTokenRead])
async def list_api_tokens(
    session: AsyncSession = Depends(get_session),
) -> Sequence[ApiToken]:
    return (await session.execute(select(ApiToken))).scalars().all()


@router.delete("/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_token(
    token_id: int, session: AsyncSession = Depends(get_session)
) -> None:
    row = await session.get(ApiToken, token_id)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="API token not found"
        )
    await session.delete(row)
    await session.commit()
