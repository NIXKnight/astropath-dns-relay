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

"""Audit-events route (SPEC §9.1, HIGH-8).

``GET /api/v1/events`` is a **read-only**, paginated view over the append-only
:class:`~astropath.models.ChallengeEvent` audit log — most recent first. The rows
carry no secrets by construction (only zone, record handle, action, provider,
result, latency, the authorizing TSIG key *id*, source IP, and a redacted error),
so this endpoint exposes the full row safely. There is no write path here: the log
is written solely by the dispatcher (T-M2-06).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import col, select

from astropath.api.auth import require_admin
from astropath.api.deps import get_session
from astropath.api.schemas import ChallengeEventPage, ChallengeEventRead
from astropath.models import ChallengeEvent

__all__ = ["router"]

router = APIRouter(
    prefix="/api/v1/events",
    tags=["events"],
    dependencies=[Depends(require_admin)],
)


@router.get("", response_model=ChallengeEventPage)
async def list_events(
    session: AsyncSession = Depends(get_session),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> ChallengeEventPage:
    total = (
        await session.execute(select(func.count()).select_from(ChallengeEvent))
    ).scalar_one()
    rows = (
        (
            await session.execute(
                select(ChallengeEvent)
                # newest first; id breaks ties for rows sharing a timestamp so
                # pagination is stable across pages.
                .order_by(col(ChallengeEvent.ts).desc(), col(ChallengeEvent.id).desc())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return ChallengeEventPage(
        items=[ChallengeEventRead.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )
