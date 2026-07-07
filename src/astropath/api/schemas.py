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

"""Request/response schemas for the management API (SPEC §9.2).

Secrets are **write-only**: accepted on create/update, **never** returned on read.
Read models therefore omit every secret-bearing field entirely (a strictly safer
form of "redacted") — provider config, HE per-record keys, TSIG secrets, and API
tokens never appear in a list/get response. Generated secrets are returned exactly
once, only in the dedicated create-response models (SPEC §9.2, §16).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "BackendCreate",
    "BackendRead",
    "BackendUpdate",
]


class BackendCreate(BaseModel):
    """Create a provider backend (shared config; SPEC §9.1)."""

    name: str = Field(min_length=1, max_length=255)
    type: str = Field(min_length=1, description="registry key, e.g. 'hurricane'")
    config: dict[str, Any] = Field(
        default_factory=dict, description="provider config per its config_schema()"
    )


class BackendUpdate(BaseModel):
    """Patch a backend's name and/or config (re-encrypted on write)."""

    name: str | None = Field(default=None, min_length=1, max_length=255)
    config: dict[str, Any] | None = None


class BackendRead(BaseModel):
    """Backend view — config is write-only and never returned (SPEC §9.2)."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    type: str
    created_at: datetime
    updated_at: datetime
