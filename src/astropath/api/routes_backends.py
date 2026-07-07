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

"""Backends CRUD routes (SPEC §9.1, HIGH-9).

``POST``/``GET``/``PATCH``/``DELETE`` ``/api/v1/backends``. ``type`` is validated
against the provider ``REGISTRY`` and the config against that provider's
``config_schema()`` (Pydantic); the config is re-encrypted under the KEK on every
write and **never** returned on read (write-only, SPEC §9.2). ``DELETE`` is a 409
when any Domain still references the backend.

Validation errors are reported by field location + message only — never the
submitted value — so a rejected secret config field is not echoed back.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from astropath.api.auth import require_admin
from astropath.api.deps import get_kek, get_session
from astropath.api.schemas import BackendCreate, BackendRead, BackendUpdate
from astropath.crypto import Kek
from astropath.models import Backend, Domain
from astropath.providers.base import UnknownProvider, get_provider
from astropath.store import SecretCodec, build_backend

__all__ = ["router"]

router = APIRouter(
    prefix="/api/v1/backends",
    tags=["backends"],
    dependencies=[Depends(require_admin)],
)


def _safe_validation_detail(exc: ValidationError) -> list[dict[str, Any]]:
    """Field-location + message only — never echo the (possibly secret) input."""
    return [
        {"loc": list(err["loc"]), "msg": err["msg"], "type": err["type"]}
        for err in exc.errors()
    ]


def _validated_config(provider_type: str, config: Mapping[str, Any]) -> dict[str, Any]:
    """Resolve the provider and validate ``config`` against its schema (SPEC §5.2)."""
    try:
        provider_cls = get_provider(provider_type)
    except UnknownProvider as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"unknown provider type {provider_type!r}",
        ) from exc
    try:
        model = provider_cls.config_schema().model_validate(dict(config))
    except ValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=_safe_validation_detail(exc),
        ) from exc
    dumped: dict[str, Any] = model.model_dump()
    return dumped


async def _get_or_404(session: AsyncSession, backend_id: int) -> Backend:
    backend = await session.get(Backend, backend_id)
    if backend is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="backend not found"
        )
    return backend


@router.post("", response_model=BackendRead, status_code=status.HTTP_201_CREATED)
async def create_backend(
    payload: BackendCreate,
    session: AsyncSession = Depends(get_session),
    kek: Kek = Depends(get_kek),
) -> Backend:
    config = _validated_config(payload.type, payload.config)
    backend = build_backend(
        SecretCodec(kek), name=payload.name, backend_type=payload.type, config=config
    )
    session.add(backend)
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"backend name {payload.name!r} already exists",
        ) from exc
    await session.refresh(backend)
    return backend


@router.get("", response_model=list[BackendRead])
async def list_backends(
    session: AsyncSession = Depends(get_session),
) -> Sequence[Backend]:
    return (await session.execute(select(Backend))).scalars().all()


@router.get("/{backend_id}", response_model=BackendRead)
async def get_backend(
    backend_id: int, session: AsyncSession = Depends(get_session)
) -> Backend:
    return await _get_or_404(session, backend_id)


@router.patch("/{backend_id}", response_model=BackendRead)
async def update_backend(
    backend_id: int,
    payload: BackendUpdate,
    session: AsyncSession = Depends(get_session),
    kek: Kek = Depends(get_kek),
) -> Backend:
    backend = await _get_or_404(session, backend_id)
    if payload.name is not None:
        backend.name = payload.name
    if payload.config is not None:
        config = _validated_config(backend.type, payload.config)
        backend.config_encrypted = SecretCodec(kek).encrypt_json(config)
    session.add(backend)
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="backend name already exists",
        ) from exc
    await session.refresh(backend)
    return backend


@router.delete("/{backend_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_backend(
    backend_id: int, session: AsyncSession = Depends(get_session)
) -> None:
    backend = await _get_or_404(session, backend_id)
    referenced = (
        await session.execute(
            select(Domain.id).where(Domain.backend_id == backend_id).limit(1)
        )
    ).first()
    if referenced is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="backend is referenced by one or more domains",
        )
    await session.delete(backend)
    await session.commit()
