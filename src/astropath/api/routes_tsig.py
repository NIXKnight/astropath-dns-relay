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

"""TSIG-key routes (SPEC §9.1, HIGH-10, LOW-1).

``POST /api/v1/tsig-keys`` mints a fresh HMAC secret server-side and returns it in
**base64 BIND form exactly once** (the value that goes verbatim into the
cert-manager Secret so both sides key identically); the secret is KEK-encrypted at
rest. ``GET`` lists names/algorithms only — never the secret. ``DELETE`` revokes.
A lost secret is revoked and recreated, never redisplayed.
"""

from __future__ import annotations

from collections.abc import Sequence

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from astropath.api.auth import require_admin
from astropath.api.deps import get_kek, get_session
from astropath.api.schemas import TsigKeyCreate, TsigKeyCreated, TsigKeyRead
from astropath.bootstrap import generate_tsig_secret
from astropath.crypto import Kek
from astropath.data_plane.tsig import UnknownAlgorithm, algorithm_from_text
from astropath.models import TsigKey
from astropath.store import SecretCodec, build_tsig_key

__all__ = ["router"]

router = APIRouter(
    prefix="/api/v1/tsig-keys",
    tags=["tsig-keys"],
    dependencies=[Depends(require_admin)],
)


@router.post("", response_model=TsigKeyCreated, status_code=status.HTTP_201_CREATED)
async def create_tsig_key(
    payload: TsigKeyCreate,
    session: AsyncSession = Depends(get_session),
    kek: Kek = Depends(get_kek),
) -> TsigKeyCreated:
    try:
        algorithm_from_text(payload.algorithm)
    except UnknownAlgorithm as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"unsupported TSIG algorithm {payload.algorithm!r}",
        ) from exc

    secret_b64 = generate_tsig_secret()  # base64 BIND form — revealed once
    row = build_tsig_key(
        SecretCodec(kek),
        name=payload.name,
        algorithm=payload.algorithm,
        secret_b64=secret_b64,
    )
    session.add(row)
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"TSIG key name {payload.name!r} already exists",
        ) from exc
    await session.refresh(row)
    assert row.id is not None
    return TsigKeyCreated(
        id=row.id,
        name=row.name,
        algorithm=row.algorithm,
        created_at=row.created_at,
        secret=secret_b64,
    )


@router.get("", response_model=list[TsigKeyRead])
async def list_tsig_keys(
    session: AsyncSession = Depends(get_session),
) -> Sequence[TsigKey]:
    return (await session.execute(select(TsigKey))).scalars().all()


@router.delete("/{tsig_key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_tsig_key(
    tsig_key_id: int, session: AsyncSession = Depends(get_session)
) -> None:
    row = await session.get(TsigKey, tsig_key_id)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="TSIG key not found"
        )
    await session.delete(row)
    await session.commit()
