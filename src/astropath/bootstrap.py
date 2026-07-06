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

"""M1 file/env bootstrap loader (SPEC §16, MED-8, HIGH-7).

M1 ships the data plane with no DB: the keyring and zone→provider routing are
loaded from a TOML bootstrap file whose secrets are KEK-encrypted at rest
(SPEC §16.2). :func:`build_data_plane` turns a loaded config into the exact
runtime objects (keyring of ``Key`` objects, :class:`RoutingTable`, provider
instances) that M2 will later build from the database — the same code path, a
different source.

TOML (not YAML) is used so no new dependency is required (stdlib ``tomllib``);
SPEC §16.1 permits "YAML/TOML". Secret discipline: decrypted secrets live in
memory only and are never logged.

File shape::

    [listener]
    host = "0.0.0.0"
    port = 53

    [[tsig_keys]]
    name = "cm-key."
    algorithm = "hmac-sha256"
    secret = "<KEK-encrypted base64 BIND secret>"

    [[zones]]
    zone = "example.com."
    provider = "hurricane"
    record_name = "_acme-challenge.example.com."
    he_dynamic_key = "<KEK-encrypted per-record key>"   # omit for Route53
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

import dns.name
import dns.tsig
import httpx

from astropath.crypto import Kek
from astropath.data_plane.dispatcher import Route, RoutingTable
from astropath.data_plane.tsig import DEFAULT_ALGORITHM, TsigKeySpec, build_keyring
from astropath.providers.base import Provider, get_provider
from astropath.providers.hurricane import HurricaneProvider

__all__ = [
    "BootstrapConfig",
    "BootstrapError",
    "DataPlaneRuntime",
    "ZoneConfig",
    "build_data_plane",
    "load_bootstrap",
]

Keyring = dict[dns.name.Name, dns.tsig.Key]


class BootstrapError(ValueError):
    """The bootstrap file is missing required fields or is malformed."""


@dataclass(frozen=True)
class ZoneConfig:
    """One zone → provider mapping with a decrypted per-record secret."""

    zone: str
    provider: str
    record_name: str
    he_dynamic_key: str | None = None  # decrypted; redact in any diagnostic


@dataclass(frozen=True)
class BootstrapConfig:
    """Decrypted bootstrap contents (secrets in memory only)."""

    tsig_keys: list[TsigKeySpec] = field(default_factory=list)
    zones: list[ZoneConfig] = field(default_factory=list)
    listener_host: str = "0.0.0.0"
    listener_port: int = 53


@dataclass
class DataPlaneRuntime:
    """Runtime objects the data plane serves from (file in M1, DB in M2)."""

    keyring: Keyring
    routing: RoutingTable
    providers: list[Provider]


def load_bootstrap(path: str | Path, kek: Kek) -> BootstrapConfig:
    """Parse ``path`` and decrypt its secrets with ``kek`` (SPEC §16).

    Raises :class:`FileNotFoundError` if absent, :class:`BootstrapError` on a
    malformed document, and :class:`cryptography.fernet.InvalidToken` if a
    secret does not decrypt under the KEK. Never logs secret material.
    """
    raw = Path(path).read_bytes()
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise BootstrapError(f"bootstrap file is not valid TOML: {exc}") from exc

    listener = data.get("listener", {})
    tsig_keys: list[TsigKeySpec] = []
    for entry in data.get("tsig_keys", []):
        try:
            tsig_keys.append(
                TsigKeySpec(
                    name=entry["name"],
                    algorithm=entry.get("algorithm", DEFAULT_ALGORITHM),
                    secret_b64=kek.decrypt_str(entry["secret"]),
                )
            )
        except KeyError as exc:
            raise BootstrapError(f"tsig_keys entry missing field {exc}") from exc

    zones: list[ZoneConfig] = []
    for entry in data.get("zones", []):
        try:
            he_token = entry.get("he_dynamic_key")
            zones.append(
                ZoneConfig(
                    zone=entry["zone"],
                    provider=entry["provider"],
                    record_name=entry["record_name"],
                    he_dynamic_key=(kek.decrypt_str(he_token) if he_token else None),
                )
            )
        except KeyError as exc:
            raise BootstrapError(f"zones entry missing field {exc}") from exc

    return BootstrapConfig(
        tsig_keys=tsig_keys,
        zones=zones,
        listener_host=str(listener.get("host", "0.0.0.0")),
        listener_port=int(listener.get("port", 53)),
    )


def build_data_plane(
    config: BootstrapConfig, *, http_client: httpx.AsyncClient
) -> DataPlaneRuntime:
    """Build the keyring + routing + providers from a loaded config (SPEC §16).

    One provider instance is created per provider type (sharing the long-lived
    HTTP client); HE per-record dynamic keys are injected per zone (domain-scoped
    credential, HIGH-7). This is the shared runtime path M2 reuses from the DB.
    """
    keyring = build_keyring(config.tsig_keys)
    providers: dict[str, Provider] = {}
    routes: list[Route] = []

    for zone_config in config.zones:
        provider = providers.get(zone_config.provider)
        if provider is None:
            provider_cls = get_provider(zone_config.provider)
            provider = provider_cls.from_config({}, http=http_client)
            providers[zone_config.provider] = provider

        if isinstance(provider, HurricaneProvider) and zone_config.he_dynamic_key:
            provider.register_record_key(
                zone_config.record_name, zone_config.he_dynamic_key
            )

        routes.append(
            Route(
                zone=dns.name.from_text(zone_config.zone).canonicalize(),
                provider=provider,
                record_name=dns.name.from_text(zone_config.record_name).canonicalize(),
            )
        )

    return DataPlaneRuntime(
        keyring=keyring,
        routing=RoutingTable(routes),
        providers=list(providers.values()),
    )
