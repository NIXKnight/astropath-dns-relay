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

"""Provider ABC and the module-level registry (SPEC §5.1, §5.2, HIGH-9).

A provider translates a validated ACME DNS-01 challenge into a backend write
(HTTP for Hurricane Electric, SDK for Route53). Adding a provider is one new
file plus one :func:`register` decorator; ``config_schema()`` (a Pydantic model)
drives both API validation and the SPA credential form.

Contract highlights:

- ``present``/``cleanup`` are **idempotent** (SPEC §5.3): re-presenting the same
  value or cleaning an absent one is success.
- Endpoints are **fixed in the provider class** (SPEC §5.5) — no user-supplied
  URLs (SSRF closed). ``config_schema()`` never accepts a URL field.
- ``present``/``cleanup`` take ``values: list[str]`` (SPEC §5.4); M1 passes a
  single-element list. ``supports_multivalue`` gates >1 value.
- On any provider-side failure they raise :class:`ProviderError`; the dispatcher
  maps that to SERVFAIL (SPEC §3.6).

Secret discipline: providers hold decrypted credentials in memory only and must
never log, echo, or otherwise propagate them; redact to ``<REDACTED>``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Any, ClassVar, TypeAlias

from pydantic import BaseModel

# ``type`` is a ClassVar attribute name on Provider (SPEC §5.1), which shadows
# the builtin inside the class body. This module-scope alias lets return
# annotations name "a Pydantic model class" without touching the shadowed name.
ConfigSchema: TypeAlias = type[BaseModel]

__all__ = [
    "REGISTRY",
    "ConfigSchema",
    "Provider",
    "ProviderError",
    "UnknownProvider",
    "get_provider",
    "register",
]


class ProviderError(Exception):
    """A provider backend call failed (mapped to SERVFAIL by the dispatcher)."""


class UnknownProvider(KeyError):
    """A backend ``type`` does not resolve to a registered provider."""


class Provider(ABC):
    """Abstract DNS provider backend (SPEC §5.1)."""

    #: Registry key, e.g. ``"hurricane"`` / ``"route53"``.
    type: ClassVar[str]
    #: Whether the provider can hold >1 TXT value on one name concurrently.
    supports_multivalue: ClassVar[bool] = False
    #: Whether real deletion is supported (HE overrides to False; §5.7).
    supports_delete: ClassVar[bool] = True

    @classmethod
    @abstractmethod
    def config_schema(cls) -> ConfigSchema:
        """Return the Pydantic model describing this provider's backend config."""

    @classmethod
    @abstractmethod
    def from_config(cls, config: Mapping[str, Any], *, http: Any) -> Provider:
        """Build an instance from validated config and a shared client.

        ``http`` is the provider-specific shared client created once by
        ``main()`` (an ``httpx.AsyncClient`` for HE; an aiobotocore session for
        Route53) — providers pool connections through it (SPEC §5.6).
        """

    @abstractmethod
    async def present(self, zone: str, record_name: str, values: list[str]) -> None:
        """Publish the challenge TXT value(s) (idempotent; SPEC §5.3)."""

    @abstractmethod
    async def cleanup(self, zone: str, record_name: str, values: list[str]) -> None:
        """Remove/overwrite the challenge TXT value(s) (idempotent; SPEC §5.3)."""

    @abstractmethod
    async def validate(self) -> None:
        """Credential dry-run; raise :class:`ProviderError` on bad credentials."""


REGISTRY: dict[str, type[Provider]] = {}


def register(cls: type[Provider]) -> type[Provider]:
    """Class decorator registering ``cls`` under its ``type`` key (SPEC §5.2)."""
    key = cls.type
    if key in REGISTRY and REGISTRY[key] is not cls:
        raise ValueError(f"provider type {key!r} already registered")
    REGISTRY[key] = cls
    return cls


def get_provider(provider_type: str) -> type[Provider]:
    """Resolve a provider class by ``type`` (rejects unknown types; SPEC §5.2)."""
    try:
        return REGISTRY[provider_type]
    except KeyError as exc:
        raise UnknownProvider(
            f"unknown provider type {provider_type!r}; "
            f"registered: {sorted(REGISTRY)}"
        ) from exc
