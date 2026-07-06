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

"""Startup configuration fail-fast (SPEC §16, LOW-5, T-M1-26).

Every precondition that can be checked cheaply is checked *before* the process
binds its readiness — a misconfigured relay must crash loudly at boot, never
half-serve. The M1 subset validates:

* the KEK keylist entries are valid 32-byte urlsafe-base64 Fernet keys,
* the bootstrap file is present and decrypts under that KEK,
* every configured provider type resolves in the provider ``REGISTRY``,
* every configured TSIG algorithm maps to a dnspython algorithm.

All failures raise :class:`StartupError` with a message that names the offending
zone / provider / algorithm / key **position** — never a secret value. M6
(:mod:`T-M6-10`) extends this to the database world; the shape stays identical.
"""

from __future__ import annotations

from pathlib import Path

from astropath.bootstrap import BootstrapConfig, BootstrapError, load_bootstrap
from astropath.crypto import InvalidToken, Kek, KekError
from astropath.data_plane.tsig import UnknownAlgorithm, algorithm_from_text
from astropath.providers.base import UnknownProvider, get_provider

__all__ = ["StartupError", "validate_and_load"]


class StartupError(RuntimeError):
    """A startup precondition failed; the process must not bind readiness.

    Messages are safe to log: they identify configuration by zone, provider,
    algorithm, or key *position*, and never carry a decrypted secret.
    """


def validate_and_load(
    kek_keylist: str | None, bootstrap_path: str | Path | None
) -> tuple[Kek, BootstrapConfig]:
    """Validate the M1 startup preconditions and return ``(kek, config)``.

    Raises :class:`StartupError` on any failure — malformed KEK, missing or
    undecryptable bootstrap file, an unknown provider type, or an unsupported
    TSIG algorithm. On success the returned pair is ready for
    :func:`astropath.bootstrap.build_data_plane`; nothing else needs to re-parse
    or re-decrypt.
    """
    if not kek_keylist:
        raise StartupError(
            "credential KEK is not configured (set ASTROPATH_CREDENTIAL_KEK)"
        )
    try:
        kek = Kek.from_keylist(kek_keylist)
    except KekError as exc:
        # KekError already redacts to key position; never echo the raw keylist.
        raise StartupError(f"invalid credential KEK: {exc}") from exc

    if bootstrap_path is None:
        raise StartupError(
            "bootstrap path is not configured (set ASTROPATH_BOOTSTRAP_PATH)"
        )
    path = Path(bootstrap_path)
    if not path.is_file():
        raise StartupError(f"bootstrap file not found: {path}")

    try:
        config = load_bootstrap(path, kek)
    except BootstrapError as exc:
        raise StartupError(f"bootstrap file is invalid: {exc}") from exc
    except InvalidToken as exc:
        # Wrong KEK for the stored ciphertext — message carries no secret.
        raise StartupError(
            f"bootstrap secrets do not decrypt under the configured KEK: {path}"
        ) from exc

    for zone in config.zones:
        try:
            get_provider(zone.provider)
        except UnknownProvider as exc:
            raise StartupError(
                f"zone {zone.zone!r} references unknown provider {zone.provider!r}"
            ) from exc

    for spec in config.tsig_keys:
        try:
            algorithm_from_text(spec.algorithm)
        except UnknownAlgorithm as exc:
            raise StartupError(
                f"TSIG key {spec.name!r} uses unsupported algorithm "
                f"{spec.algorithm!r}"
            ) from exc

    return kek, config
