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

"""Algorithm-bound TSIG keyring construction (SPEC §3.1, BLOCKER-1).

The keyring maps ``dns.name.Name`` → explicit ``dns.tsig.Key`` objects, **never**
``name → raw bytes``. This is a security property (SPEC §3.1): a raw-bytes value
makes ``dns.message.from_wire`` construct the key with the algorithm read from
the *inbound wire* (attacker-influenced); a pre-built ``Key`` binds the algorithm
server-side and the wire algorithm is enforced (a mismatch is rejected, not
silently downgraded — proven in :mod:`tests.test_dnspython_asserts`).

The stored/config algorithm form is the dashed RFC8945 name ``hmac-sha256``
(the dnspython/DNS-wire spelling). cert-manager's dashless CRD spelling
``HMACSHA256`` is a boundary translation only (SPEC §14.1); :func:`algorithm_from_text`
accepts both for robustness.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

import dns.name
import dns.tsig

__all__ = [
    "DEFAULT_ALGORITHM",
    "SUPPORTED_ALGORITHMS",
    "TsigKeySpec",
    "UnknownAlgorithm",
    "algorithm_from_text",
    "build_keyring",
]

DEFAULT_ALGORITHM = "hmac-sha256"

# Dashed RFC8945 text form → dnspython algorithm name. hmac-sha256 is the
# canonical choice for astropath (SPEC §3.1); the wider set is accepted so an
# operator is not silently locked out if they configure another HMAC.
SUPPORTED_ALGORITHMS: dict[str, dns.name.Name] = {
    "hmac-sha256": dns.tsig.HMAC_SHA256,
    "hmac-sha384": dns.tsig.HMAC_SHA384,
    "hmac-sha512": dns.tsig.HMAC_SHA512,
    "hmac-sha224": dns.tsig.HMAC_SHA224,
    "hmac-sha1": dns.tsig.HMAC_SHA1,
    "hmac-md5": dns.tsig.HMAC_MD5,
}


class UnknownAlgorithm(ValueError):
    """A configured TSIG algorithm has no dnspython mapping (fail-fast)."""


def _normalize_algorithm(text: str) -> str:
    """Normalize an algorithm string to the dashed lower-case form.

    Accepts the dashed wire form (``hmac-sha256``, optional trailing dot, any
    case) and cert-manager's dashless CRD spelling (``HMACSHA256``).
    """
    normalized = text.strip().rstrip(".").lower()
    if normalized in SUPPORTED_ALGORITHMS:
        return normalized
    # cert-manager dashless form, e.g. "hmacsha256" -> "hmac-sha256"
    if normalized.startswith("hmac") and "-" not in normalized:
        candidate = "hmac-" + normalized[len("hmac") :]
        if candidate in SUPPORTED_ALGORITHMS:
            return candidate
    return normalized


def algorithm_from_text(text: str) -> dns.name.Name:
    """Map an algorithm string to its dnspython ``dns.name.Name`` constant.

    Raises :class:`UnknownAlgorithm` (redacting nothing sensitive — the
    algorithm name is not a secret) when unmapped.
    """
    normalized = _normalize_algorithm(text)
    try:
        return SUPPORTED_ALGORITHMS[normalized]
    except KeyError as exc:
        raise UnknownAlgorithm(
            f"unsupported TSIG algorithm {text!r}; "
            f"expected one of {sorted(SUPPORTED_ALGORITHMS)}"
        ) from exc


@dataclass(frozen=True)
class TsigKeySpec:
    """One TSIG key as stored in config (SPEC §3.1, §10, §16).

    ``secret_b64`` is the base64 BIND-form secret (what cert-manager also holds).
    It is redacted to ``<REDACTED>`` in every diagnostic path; this dataclass
    never overrides ``__repr__`` to expose it and callers must not log it.
    """

    name: str
    algorithm: str = DEFAULT_ALGORITHM
    secret_b64: str = ""


def build_keyring(specs: Iterable[TsigKeySpec]) -> dict[dns.name.Name, dns.tsig.Key]:
    """Build a ``name → dns.tsig.Key`` keyring with per-key bound algorithms.

    Each value is an explicit :class:`dns.tsig.Key` so the HMAC algorithm is
    fixed server-side (SPEC §3.1). Raises :class:`UnknownAlgorithm` on an
    unmapped algorithm (fail-fast, T-M1-26).
    """
    keyring: dict[dns.name.Name, dns.tsig.Key] = {}
    for spec in specs:
        algorithm = algorithm_from_text(spec.algorithm)
        name = dns.name.from_text(spec.name)
        keyring[name] = dns.tsig.Key(name, spec.secret_b64, algorithm=algorithm)
    return keyring
