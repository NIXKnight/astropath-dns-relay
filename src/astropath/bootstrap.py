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

import argparse
import base64
import os
import secrets
import sys
import tomllib
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TextIO

import dns.name
import dns.tsig
import httpx

from astropath.crypto import Kek, generate_key
from astropath.data_plane.dispatcher import Route, RoutingTable
from astropath.data_plane.tsig import (
    DEFAULT_ALGORITHM,
    TsigKeySpec,
    algorithm_from_text,
    build_keyring,
)
from astropath.providers.base import Provider, get_provider
from astropath.providers.hurricane import HurricaneProvider

__all__ = [
    "BootstrapConfig",
    "BootstrapError",
    "DataPlaneRuntime",
    "ZoneConfig",
    "build_data_plane",
    "generate_tsig_secret",
    "load_bootstrap",
    "main",
    "render_secret_yaml",
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


# --------------------------------------------------------------------------- #
# astropath-bootstrap CLI (SPEC §16.1, MED-8, LOW-1)
# --------------------------------------------------------------------------- #
def generate_tsig_secret() -> str:
    """Mint a fresh 32-byte HMAC secret in base64 BIND form.

    This base64 string is what goes verbatim into the cert-manager Secret and
    the M1 bootstrap file — cert-manager and dnspython key from it identically.
    """
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


def render_secret_yaml(
    secret_b64: str,
    *,
    name: str = "tsig-secret",
    key: str = "tsig-secret-key",
    namespace: str = "cert-manager",
) -> str:
    """Render the cert-manager TSIG Secret in ``stringData`` form (SPEC §14.5).

    ``stringData`` (never a hand-encoded ``.data``) avoids the double-base64 trap
    that yields BADKEY/BADSIG. The Secret lives in the cluster-resource namespace.
    """
    return (
        "apiVersion: v1\n"
        "kind: Secret\n"
        "metadata:\n"
        f"  name: {name}\n"
        f"  namespace: {namespace}\n"
        "type: Opaque\n"
        "stringData:\n"
        f"  {key}: {secret_b64}\n"
    )


def _render_bootstrap_toml(
    *,
    tsig_name: str,
    algorithm: str,
    tsig_secret_token: str,
    zone: str,
    provider: str,
    record_name: str,
    he_key_token: str | None,
    host: str,
    port: int,
) -> str:
    lines = [
        "# AstropathDNSRelay M1 bootstrap (SPEC §16). Secrets are KEK-encrypted;",
        "# deliver ansible-vault'd. Never commit a real secret to git.",
        "",
        "[listener]",
        f'host = "{host}"',
        f"port = {port}",
        "",
        "[[tsig_keys]]",
        f'name = "{tsig_name}"',
        f'algorithm = "{algorithm}"',
        f'secret = "{tsig_secret_token}"',
        "",
        "[[zones]]",
        f'zone = "{zone}"',
        f'provider = "{provider}"',
        f'record_name = "{record_name}"',
    ]
    if he_key_token is not None:
        lines.append(f'he_dynamic_key = "{he_key_token}"')
    else:
        lines.append(
            '# he_dynamic_key = "<KEK-encrypted HE dynamic key>"  '
            "# add for a hurricane zone"
        )
    return "\n".join(lines) + "\n"


def _require_kek() -> Kek:
    raw = os.environ.get("ASTROPATH_CREDENTIAL_KEK")
    if not raw:
        raise BootstrapError(
            "ASTROPATH_CREDENTIAL_KEK is not set; a KEK is required to encrypt "
            "bootstrap secrets at rest"
        )
    return Kek.from_keylist(raw)


def _cmd_gen_kek(args: argparse.Namespace, out: TextIO) -> int:
    # One-time reveal: the KEK is shown once; store it ansible-vault'd.
    out.write(generate_key() + "\n")
    return 0


def _cmd_gen_tsig(args: argparse.Namespace, out: TextIO) -> int:
    secret = generate_tsig_secret()
    # Validate the algorithm maps (fail loudly on a typo before emitting).
    algorithm_from_text(args.algorithm)
    out.write(f"key_name: {args.name}\n")
    out.write(f"algorithm: {args.algorithm}\n")
    out.write(f"secret: {secret}\n")  # base64 BIND form — shown ONCE by design
    if args.k8s_secret:
        out.write("---\n")
        out.write(render_secret_yaml(secret, key=args.secret_key))
    return 0


def _cmd_secret_yaml(args: argparse.Namespace, out: TextIO) -> int:
    out.write(render_secret_yaml(args.secret, name=args.name, key=args.secret_key))
    return 0


def _cmd_init(args: argparse.Namespace, out: TextIO) -> int:
    kek = _require_kek()
    secret = generate_tsig_secret()
    algorithm_from_text(args.algorithm)  # validate before writing

    he_token = kek.encrypt_str(args.he_key) if args.he_key else None
    document = _render_bootstrap_toml(
        tsig_name=args.name,
        algorithm=args.algorithm,
        tsig_secret_token=kek.encrypt_str(secret),
        zone=args.zone,
        provider=args.provider,
        record_name=args.record_name,
        he_key_token=he_token,
        host=args.host,
        port=args.port,
    )
    Path(args.output).write_text(document, encoding="utf-8")

    # One-time reveal of the plaintext TSIG secret for the cert-manager Secret.
    out.write(f"# wrote bootstrap file: {args.output}\n")
    out.write(f"# TSIG key_name: {args.name}  algorithm: {args.algorithm}\n")
    out.write(f"# TSIG secret (base64 BIND, shown ONCE): {secret}\n")
    out.write("# lost? revoke and recreate — the secret is never redisplayed.\n")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="astropath-bootstrap",
        description="Generate M1 TSIG keys, KEK, cert-manager Secret, and the "
        "bootstrap file (secrets are shown once).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_kek = sub.add_parser("gen-kek", help="generate a Fernet KEK key")
    p_kek.set_defaults(func=_cmd_gen_kek)

    p_tsig = sub.add_parser("gen-tsig", help="mint a TSIG key (secret shown once)")
    p_tsig.add_argument("--name", default="astropath-tsig.")
    p_tsig.add_argument("--algorithm", default=DEFAULT_ALGORITHM)
    p_tsig.add_argument("--k8s-secret", action="store_true", help="also emit Secret")
    p_tsig.add_argument("--secret-key", default="tsig-secret-key")
    p_tsig.set_defaults(func=_cmd_gen_tsig)

    p_secret = sub.add_parser("secret-yaml", help="emit a cert-manager TSIG Secret")
    p_secret.add_argument("--secret", required=True, help="base64 BIND secret")
    p_secret.add_argument("--name", default="tsig-secret")
    p_secret.add_argument("--secret-key", default="tsig-secret-key")
    p_secret.set_defaults(func=_cmd_secret_yaml)

    p_init = sub.add_parser("init", help="write a starter bootstrap file")
    p_init.add_argument("--output", required=True)
    p_init.add_argument("--name", default="astropath-tsig.")
    p_init.add_argument("--algorithm", default=DEFAULT_ALGORITHM)
    p_init.add_argument("--zone", required=True)
    p_init.add_argument("--provider", default="hurricane")
    p_init.add_argument("--record-name", required=True)
    p_init.add_argument("--he-key", default=None, help="HE dynamic key (encrypted)")
    p_init.add_argument("--host", default="0.0.0.0")
    p_init.add_argument("--port", type=int, default=53)
    p_init.set_defaults(func=_cmd_init)
    return parser


def main(argv: Sequence[str] | None = None, *, out: TextIO | None = None) -> int:
    """``python -m astropath.bootstrap`` entrypoint (SPEC §16.1)."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args, out if out is not None else sys.stdout))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
