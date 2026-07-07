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

"""Domains CRUD routes (SPEC §9.1, HIGH-7).

``POST``/``GET``/``DELETE`` ``/api/v1/domains`` maps a zone to a backend plus a
provider record handle and the **domain-scoped** HE per-record dynamic key
(HIGH-7 — stored on the Domain, not the Backend). The key is accepted on create,
KEK-encrypted at rest, and **never** returned on read; a read exposes only whether
a key is present.
"""

from __future__ import annotations

from collections.abc import Sequence

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from astropath.api.auth import require_admin
from astropath.api.deps import (
    get_kek,
    get_optional_cache,
    get_session,
    refresh_routing_cache,
)
from astropath.api.schemas import DomainCreate, DomainRead
from astropath.cache import RoutingCache
from astropath.crypto import Kek
from astropath.models import Backend, Domain
from astropath.store import SecretCodec, build_domain

__all__ = ["router"]

router = APIRouter(
    prefix="/api/v1/domains",
    tags=["domains"],
    dependencies=[Depends(require_admin)],
)


def _to_read(domain: Domain) -> DomainRead:
    """Project a Domain to its read view, exposing only presence of the secret."""
    assert domain.id is not None
    return DomainRead(
        id=domain.id,
        zone=domain.zone,
        backend_id=domain.backend_id,
        record_name=domain.record_name,
        created_at=domain.created_at,
        has_secret=domain.secret_encrypted is not None,
    )


@router.post("", response_model=DomainRead, status_code=status.HTTP_201_CREATED)
async def create_domain(
    payload: DomainCreate,
    session: AsyncSession = Depends(get_session),
    kek: Kek = Depends(get_kek),
    cache: RoutingCache | None = Depends(get_optional_cache),
) -> DomainRead:
    if await session.get(Backend, payload.backend_id) is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"backend {payload.backend_id} does not exist",
        )
    domain = build_domain(
        SecretCodec(kek),
        zone=payload.zone,
        backend_id=payload.backend_id,
        record_name=payload.record_name,
        he_dynamic_key=payload.he_dynamic_key,
    )
    session.add(domain)
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"zone {payload.zone!r} is already mapped",
        ) from exc
    await session.refresh(domain)
    # zone -> backend routing changed; make it visible to the DNS plane now.
    await refresh_routing_cache(cache)
    return _to_read(domain)


@router.get("", response_model=list[DomainRead])
async def list_domains(
    session: AsyncSession = Depends(get_session),
) -> Sequence[DomainRead]:
    rows = (await session.execute(select(Domain))).scalars().all()
    return [_to_read(row) for row in rows]


@router.delete("/{domain_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_domain(
    domain_id: int,
    session: AsyncSession = Depends(get_session),
    cache: RoutingCache | None = Depends(get_optional_cache),
) -> None:
    domain = await session.get(Domain, domain_id)
    if domain is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="domain not found"
        )
    await session.delete(domain)
    await session.commit()
    await refresh_routing_cache(cache)
