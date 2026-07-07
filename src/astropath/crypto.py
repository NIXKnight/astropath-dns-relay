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

"""KEK / direct key encryption for credentials at rest (SPEC §7).

Fernet + ``MultiFernet`` for KEK rotation (SPEC §7.1):

- encrypt under the **primary** (first) key;
- ``decrypt()`` tries each key in list order (reads old-key ciphertext natively,
  so rotation needs **no** schema/version column);
- ``rotate()`` re-encrypts a token under the primary key, preserving the
  original creation timestamp;
- at-rest decrypt passes **no** ``ttl`` (SPEC §7.1) — a ``ttl`` would spuriously
  reject aged stored secrets.

This is *direct* key encryption, deliberately **not** called "envelope"
encryption (SPEC §7.2). The AES-256-GCM alternative (SPEC §7.2) is not built
because Fernet/AES-128 is the locked default.

Secret discipline: this module handles plaintext secrets in memory only. It
never logs, and error messages never embed key or plaintext material (redacted
to key *positions*, never values).
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

__all__ = ["InvalidToken", "Kek", "KekError", "generate_key", "parse_keylist"]

# Split a KEK env value into ordered keys on commas and/or whitespace.
_KEYLIST_SPLIT = re.compile(r"[\s,]+")


class KekError(ValueError):
    """A KEK keylist is empty or contains an invalid Fernet key.

    Raised at startup fail-fast (SPEC §11.3 / T-M1-26). The message identifies
    the offending key by **position**, never by value (secret discipline).
    """


def generate_key() -> str:
    """Return a fresh urlsafe-base64 Fernet key (32 bytes → 44-char string)."""
    return Fernet.generate_key().decode("ascii")


def parse_keylist(raw: str) -> list[str]:
    """Parse an ordered KEK keylist (primary first) from one env string.

    Keys are separated by commas and/or whitespace (SPEC §7.3: the env var holds
    an ordered list). Empty entries are dropped; order is preserved.
    """
    return [entry for entry in _KEYLIST_SPLIT.split(raw.strip()) if entry]


def _build_fernets(keys: Sequence[str]) -> list[Fernet]:
    if not keys:
        raise KekError("KEK keylist is empty; at least one Fernet key is required")
    fernets: list[Fernet] = []
    for index, key in enumerate(keys):
        try:
            fernets.append(Fernet(key))
        except (ValueError, TypeError) as exc:
            # Never echo the key value — identify by position only.
            raise KekError(
                f"KEK key at position {index} is not a valid 32-byte "
                "urlsafe-base64 Fernet key"
            ) from exc
    return fernets


class Kek:
    """A key-encryption key backed by ``MultiFernet`` over an ordered keylist.

    The first key is primary (used for all new encryptions and for ``rotate``);
    every key participates in decryption so freshly-prepended keys can read
    ciphertext written by retired ones.
    """

    __slots__ = ("_multi",)

    def __init__(self, keys: Sequence[str]) -> None:
        self._multi = MultiFernet(_build_fernets(keys))

    @classmethod
    def from_keylist(cls, raw: str) -> Kek:
        """Build from a single env string (comma/whitespace separated)."""
        return cls(parse_keylist(raw))

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt under the primary key; return the Fernet token bytes."""
        return self._multi.encrypt(plaintext)

    def decrypt(self, token: bytes) -> bytes:
        """Decrypt at-rest ciphertext with **no** ``ttl`` (SPEC §7.1).

        Tries each key in list order; raises
        :class:`cryptography.fernet.InvalidToken` only if none match.
        """
        return self._multi.decrypt(token)

    def encrypt_str(self, text: str) -> str:
        """Encrypt a UTF-8 string; return the ascii token string."""
        return self.encrypt(text.encode("utf-8")).decode("ascii")

    def decrypt_str(self, token: str) -> str:
        """Decrypt an ascii token string back to its UTF-8 plaintext."""
        return self.decrypt(token.encode("ascii")).decode("utf-8")

    def rotate(self, token: bytes) -> bytes:
        """Re-encrypt ``token`` under the primary key (timestamp preserved).

        Lazily migrate ciphertext on access and persist the returned token
        (SPEC §7.1 / §7.3 rotation runbook).
        """
        return self._multi.rotate(token)
