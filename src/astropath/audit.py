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

"""Database audit sink for challenge events (T-M2-06, HIGH-8, SPEC §6.1).

:class:`DbAuditSink` implements the dispatcher's structural ``AuditSink`` protocol
by turning an :class:`~astropath.data_plane.dispatcher.AuditRecord` into an
**append-only** :class:`~astropath.models.ChallengeEvent` and inserting it. It only
ever inserts (never updates/deletes) — that is the append-only invariant.

The dispatcher isolates failures of this sink (a failed insert is logged and
counted, never propagated) so a Postgres blip can never break the DNS answer path
(HIGH-8). Rows carry no secrets — the ``AuditRecord`` already excludes them.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from astropath.data_plane.dispatcher import AuditRecord
from astropath.models import ChallengeEvent

__all__ = ["DbAuditSink"]


class DbAuditSink:
    """Persists challenge audit rows to Postgres (append-only)."""

    __slots__ = ("_sessionmaker",)

    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession]) -> None:
        self._sessionmaker = sessionmaker

    async def record(self, record: AuditRecord) -> None:
        """Insert one :class:`ChallengeEvent` for a challenge outcome."""
        event = ChallengeEvent(
            zone=record.zone,
            record_name=record.record_name,
            action=record.action,
            provider=record.provider,
            result=record.result,
            latency_ms=record.latency_ms,
            tsig_key_id=record.tsig_key_id,
            source=record.source,
            error_detail=record.error_detail,
        )
        async with self._sessionmaker() as session:
            session.add(event)
            await session.commit()
