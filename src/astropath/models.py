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

"""SQLModel persistence models (SPEC §6, HIGH-7, HIGH-8).

``table=True`` models on ``postgresql+asyncpg``. Importing this module registers
every table on ``SQLModel.metadata`` — the object Alembic's ``env.py`` uses as
``target_metadata`` (SPEC §12.1).

Storage rules (SPEC §6.2, encrypt-vs-hash):

- **Reversibly encrypted** (KEK/MultiFernet, ciphertext-only at rest, decrypted
  in memory at use): :attr:`Backend.config_encrypted`,
  :attr:`Domain.secret_encrypted` (the HE per-record dynamic key — domain-scoped
  per HIGH-7, **not** on ``Backend``), :attr:`TsigKey.secret_encrypted` (the HMAC
  secret must stay reversible for verification).
- **One-way hashed** (never recoverable): :attr:`ApiToken.token_hash` (SHA-256 of
  a high-entropy random token), :attr:`AdminCredential.password_hash` (argon2id).

:class:`ChallengeEvent` is an **append-only** audit table (HIGH-8): rows are only
ever inserted, never updated or deleted, and carry **no secret material**. That
invariant is a convention enforced by the store layer, not a DB trigger in M2.

All timestamps are timezone-aware (``TIMESTAMPTZ``); application-side
``default_factory`` stamps them in UTC so the values are explicit and portable.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Column, DateTime, ForeignKey, Integer, LargeBinary
from sqlmodel import Field, SQLModel

__all__ = [
    "AdminCredential",
    "ApiToken",
    "Backend",
    "ChallengeEvent",
    "Domain",
    "TsigKey",
]


def _utcnow() -> datetime:
    """Return the current time as a timezone-aware UTC ``datetime``."""
    return datetime.now(UTC)


def _created_column() -> Column[Any]:
    """A non-null ``TIMESTAMPTZ`` creation-time column."""
    return Column(DateTime(timezone=True), nullable=False)


def _updated_column() -> Column[Any]:
    """A non-null ``TIMESTAMPTZ`` column that restamps on UPDATE."""
    return Column(DateTime(timezone=True), nullable=False, onupdate=_utcnow)


class Backend(SQLModel, table=True):
    """A provider backend holding only **shared** provider config (SPEC §6.1).

    ``config_encrypted`` is the KEK-encrypted JSON of the provider's shared
    credentials (e.g. Route53 access key + hosted-zone id). The Hurricane
    Electric backend holds **no** per-record secret here — that lives on
    :class:`Domain` (HIGH-7).
    """

    __tablename__ = "backend"

    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)
    type: str = Field(index=True)
    config_encrypted: bytes = Field(sa_type=LargeBinary)
    created_at: datetime = Field(default_factory=_utcnow, sa_column=_created_column())
    updated_at: datetime = Field(default_factory=_utcnow, sa_column=_updated_column())


class Domain(SQLModel, table=True):
    """A zone → backend mapping with a domain-scoped provider secret (SPEC §6.1).

    ``secret_encrypted`` holds the KEK-encrypted HE per-record dynamic key
    (HIGH-7); Route53 domains leave it ``NULL`` because their credentials live on
    the :class:`Backend`. ``record_name`` is the provider record handle
    (e.g. the HE dynamic TXT name).
    """

    __tablename__ = "domain"

    id: int | None = Field(default=None, primary_key=True)
    zone: str = Field(index=True, unique=True)
    backend_id: int = Field(foreign_key="backend.id", index=True)
    record_name: str
    secret_encrypted: bytes | None = Field(default=None, sa_type=LargeBinary)
    created_at: datetime = Field(default_factory=_utcnow, sa_column=_created_column())


class TsigKey(SQLModel, table=True):
    """A TSIG key for the RFC2136 data plane (SPEC §6.1, §8.1).

    The secret is **reversibly encrypted** (not hashed) — HMAC verification needs
    the live value (SPEC §6.2). ``algorithm`` is the dashed RFC8945 form
    (``hmac-sha256``) bound per key (SPEC §3.1). ``name`` byte-matches
    cert-manager's ``tsigKeyName``.
    """

    __tablename__ = "tsigkey"

    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)
    algorithm: str = Field(default="hmac-sha256")
    secret_encrypted: bytes = Field(sa_type=LargeBinary)
    created_at: datetime = Field(default_factory=_utcnow, sa_column=_created_column())


class ApiToken(SQLModel, table=True):
    """A management-API token, stored **one-way hashed** (SPEC §6.1, §6.2, §8.1).

    ``token_hash`` is the SHA-256 hex digest of a high-entropy random token; the
    plaintext is shown once at creation and never persisted. Auth compares in
    constant time (store layer). ``name`` is a human label.
    """

    __tablename__ = "apitoken"

    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    token_hash: str = Field(index=True, unique=True)
    created_at: datetime = Field(default_factory=_utcnow, sa_column=_created_column())
    last_used_at: datetime | None = Field(
        default=None, sa_column=Column(DateTime(timezone=True), nullable=True)
    )


class ChallengeEvent(SQLModel, table=True):
    """An append-only audit row for one challenge present/cleanup (HIGH-8, §6.1).

    Written by the dispatcher after every provider call. Carries **no secrets** —
    only the zone, record handle, action, provider, result, latency, the TSIG key
    that authorized it, the source IP, and an optional (redacted) error detail.
    ``tsig_key_id`` is ``ON DELETE SET NULL`` so revoking a key preserves history.
    """

    __tablename__ = "challengeevent"

    id: int | None = Field(default=None, primary_key=True)
    ts: datetime = Field(default_factory=_utcnow, sa_column=_created_column())
    zone: str = Field(index=True)
    record_name: str
    action: str
    provider: str
    result: str
    latency_ms: int
    tsig_key_id: int | None = Field(
        default=None,
        sa_column=Column(
            Integer,
            ForeignKey("tsigkey.id", ondelete="SET NULL"),
            nullable=True,
            index=True,
        ),
    )
    source: str
    error_detail: str | None = Field(default=None)


class AdminCredential(SQLModel, table=True):
    """The single-row admin password credential (SPEC §6.1, §6.3).

    A change-in-UI writes the new argon2id hash to the singleton row ``id=1``;
    login checks this row first and falls back to the env-seeded
    ``ASTROPATH_ADMIN_PASSWORD_HASH`` when the row is absent (SPEC §6.3).
    """

    __tablename__ = "admincredential"

    id: int = Field(default=1, primary_key=True)
    password_hash: str
    updated_at: datetime = Field(default_factory=_utcnow, sa_column=_updated_column())
