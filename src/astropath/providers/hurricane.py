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

"""Hurricane Electric dynamic-DNS provider (SPEC §5.7, HIGH-9, HIGH-7).

Fixed endpoint ``POST https://dyn.dns.he.net/nic/update`` (no user-supplied URL
— SSRF closed). Response body ``good``/``nochg`` is success; ``badauth``/
``nohost`` are hard config errors surfaced to the operator.

HE specifics:

- **One value per dynamic record** → ``supports_multivalue=False``; >1 value is
  rejected. Per-FQDN serialization (dispatcher, §3.13) prevents clobbering.
- **No delete** → ``supports_delete=False``; ``cleanup()`` overwrites the record
  with a sentinel placeholder rather than removing it.
- **Per-record dynamic key is domain-scoped** (HIGH-7): the key lives on the
  Domain, not the Backend, and is injected per ``record_name`` — never logged.
- HE has **no create-on-write**: the ``_acme-challenge`` TXT record must be
  pre-created and flagged dynamic in the HE dashboard (operator prerequisite).
"""

from __future__ import annotations

from collections.abc import Mapping

import httpx
from pydantic import BaseModel

from astropath.providers._http import post_with_retry
from astropath.providers.base import ConfigSchema, Provider, ProviderError, register

__all__ = ["HurricaneConfig", "HurricaneProvider"]

_OK_RESPONSES = frozenset({"good", "nochg"})
# HE status tokens that mean a durable operator misconfiguration, surfaced verbatim.
_HARD_ERROR_RESPONSES = frozenset({"badauth", "nohost", "!yours", "notfqdn", "abuse"})


class HurricaneConfig(BaseModel):
    """HE backend shared config.

    HE holds **no** shared secret on the Backend — the per-record dynamic key is
    domain-scoped (HIGH-7). ``cleanup_placeholder`` is the sentinel value written
    to overwrite a challenge record on cleanup (HE cannot delete).
    """

    cleanup_placeholder: str = "acme-challenge-cleared"


def _normalize_record(record_name: str) -> str:
    """HE ``hostname=`` form: lower-case, no trailing dot."""
    return record_name.rstrip(".").lower()


@register
class HurricaneProvider(Provider):
    """Hurricane Electric dynamic-DNS provider."""

    type = "hurricane"
    supports_multivalue = False
    supports_delete = False

    ENDPOINT = "https://dyn.dns.he.net/nic/update"

    def __init__(
        self,
        client: httpx.AsyncClient,
        record_keys: Mapping[str, str] | None = None,
        *,
        cleanup_placeholder: str = "acme-challenge-cleared",
    ) -> None:
        self._client = client
        # record_name (normalized FQDN) -> per-record dynamic key (secret).
        self._record_keys: dict[str, str] = {
            _normalize_record(name): key for name, key in (record_keys or {}).items()
        }
        self._cleanup_placeholder = cleanup_placeholder

    # -- registry / config ------------------------------------------------- #
    @classmethod
    def config_schema(cls) -> ConfigSchema:
        return HurricaneConfig

    @classmethod
    def from_config(
        cls, config: Mapping[str, object], *, http: httpx.AsyncClient
    ) -> HurricaneProvider:
        parsed = HurricaneConfig.model_validate(dict(config))
        return cls(http, cleanup_placeholder=parsed.cleanup_placeholder)

    def register_record_key(self, record_name: str, dynamic_key: str) -> None:
        """Bind a per-record dynamic key (domain-scoped; from bootstrap/DB)."""
        self._record_keys[_normalize_record(record_name)] = dynamic_key

    # -- provider operations ----------------------------------------------- #
    async def present(self, zone: str, record_name: str, values: list[str]) -> None:
        if len(values) != 1:
            raise ProviderError(
                f"hurricane supports exactly one TXT value per record "
                f"(got {len(values)}); supports_multivalue is False"
            )
        await self._update(record_name, values[0])

    async def cleanup(self, zone: str, record_name: str, values: list[str]) -> None:
        # HE cannot delete; overwrite with the placeholder sentinel (idempotent).
        await self._update(record_name, self._cleanup_placeholder)

    async def validate(self) -> None:
        if not self._record_keys:
            raise ProviderError("hurricane provider has no per-record dynamic keys")

    # -- internals --------------------------------------------------------- #
    def _key_for(self, record_name: str) -> str:
        try:
            return self._record_keys[_normalize_record(record_name)]
        except KeyError as exc:
            raise ProviderError(
                f"no HE dynamic key configured for record {record_name!r}"
            ) from exc

    async def _update(self, record_name: str, txt_value: str) -> None:
        hostname = _normalize_record(record_name)
        password = self._key_for(record_name)  # secret — never logged
        try:
            response = await post_with_retry(
                self._client,
                self.ENDPOINT,
                data={"hostname": hostname, "password": password, "txt": txt_value},
            )
        except httpx.HTTPError as exc:
            # Message is exception type only — no URL/credential material.
            raise ProviderError(
                f"HE request failed for {hostname!r}: {type(exc).__name__}"
            ) from exc

        if response.status_code != httpx.codes.OK:
            raise ProviderError(
                f"HE returned HTTP {response.status_code} for {hostname!r}"
            )

        status = response.text.split()[0].lower() if response.text.strip() else ""
        if status in _OK_RESPONSES:
            return
        if status in _HARD_ERROR_RESPONSES:
            raise ProviderError(f"HE rejected update for {hostname!r}: {status}")
        raise ProviderError(f"HE unexpected response for {hostname!r}: {status!r}")
