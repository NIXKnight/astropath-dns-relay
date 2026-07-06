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

"""Persistence service: encrypt-vs-hash storage integration (T-M2-03, SPEC §6.2).

This is the seam the M3 management API and the M2 dispatcher call to move secrets
between plaintext (in memory, at the point of use) and their at-rest column form.
It enforces SPEC §6.2's storage rule:

- **Reversibly encrypted** under the KEK (:class:`SecretCodec`, MultiFernet):
  ``Backend.config_encrypted`` (JSON), ``Domain.secret_encrypted`` (HE key),
  ``TsigKey.secret_encrypted`` (HMAC secret). Ciphertext-only at rest; decrypted
  in memory when the data plane needs the live value.
- **One-way hashed** (never recoverable): ``ApiToken.token_hash`` (SHA-256 of a
  high-entropy random token, constant-time compare) and
  ``AdminCredential.password_hash`` (argon2id, slow + salted).

Net effect (the AC): a database dump alone yields **no** plaintext secret; the KEK
(held separately, ansible-vault'd) is additionally required to recover the
symmetric TSIG/provider secrets, and the token/password are unrecoverable at all.

Secret discipline: plaintext lives in local variables only and is never logged.
Row builders return the encrypted/hashed model; the one-time token plaintext is
returned to the caller separately so it can be shown once and then discarded.

Event-loop note (HIGH-11): argon2 ``hash``/``verify`` are CPU+memory-bound; the
M3 login path MUST call :func:`hash_password` / :func:`verify_password` via
``asyncio.to_thread``. The functions themselves are synchronous by design.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from collections.abc import Mapping
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from astropath.crypto import Kek
from astropath.models import ApiToken, Backend, Domain, TsigKey

__all__ = [
    "SecretCodec",
    "build_api_token",
    "build_backend",
    "build_domain",
    "build_tsig_key",
    "generate_token",
    "hash_password",
    "hash_token",
    "password_needs_rehash",
    "verify_password",
    "verify_token",
]

# High-entropy API token size (bytes of randomness before urlsafe-base64).
_TOKEN_BYTES = 32

# argon2id parameters recorded explicitly (SPEC §7.4) rather than left implicit.
# These match the argon2-cffi defaults; tune per deployment hardware and record.
_ARGON2_TIME_COST = 3
_ARGON2_MEMORY_COST = 65536
_ARGON2_PARALLELISM = 4

_password_hasher = PasswordHasher(
    time_cost=_ARGON2_TIME_COST,
    memory_cost=_ARGON2_MEMORY_COST,
    parallelism=_ARGON2_PARALLELISM,
)


class SecretCodec:
    """Encrypt/decrypt helpers that bridge :class:`Kek` and ``bytes`` columns.

    All methods operate on ``bytes`` tokens (what the ``*_encrypted`` columns
    store). Decryption uses no ``ttl`` (SPEC §7.1) so aged at-rest ciphertext
    never spuriously fails.
    """

    __slots__ = ("_kek",)

    def __init__(self, kek: Kek) -> None:
        self._kek = kek

    def encrypt_text(self, text: str) -> bytes:
        """Encrypt a UTF-8 string to a Fernet token (for a ``bytes`` column)."""
        return self._kek.encrypt(text.encode("utf-8"))

    def decrypt_text(self, token: bytes) -> str:
        """Decrypt a stored token back to its UTF-8 plaintext (in memory only)."""
        return self._kek.decrypt(token).decode("utf-8")

    def encrypt_json(self, obj: Mapping[str, Any]) -> bytes:
        """Encrypt a JSON-serializable mapping (e.g. a Backend's shared config)."""
        payload = json.dumps(obj, sort_keys=True, separators=(",", ":"))
        return self._kek.encrypt(payload.encode("utf-8"))

    def decrypt_json(self, token: bytes) -> dict[str, Any]:
        """Decrypt a token back to the original mapping (in memory only)."""
        decoded: dict[str, Any] = json.loads(self._kek.decrypt(token))
        return decoded


# --------------------------------------------------------------------------- #
# One-way token hashing (SPEC §6.2, §8.1)
# --------------------------------------------------------------------------- #
def generate_token() -> str:
    """Mint a high-entropy URL-safe API token (256 bits before encoding).

    Shown once at creation (SPEC §9.2); only its :func:`hash_token` digest is
    persisted. A lost token is revoked and recreated, never redisplayed.
    """
    return secrets.token_urlsafe(_TOKEN_BYTES)


def hash_token(token: str) -> str:
    """Return the SHA-256 hex digest of ``token`` (one-way; SPEC §6.2)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_token(candidate: str, stored_hash: str) -> bool:
    """Constant-time compare of a presented token against a stored hash."""
    return hmac.compare_digest(hash_token(candidate), stored_hash)


# --------------------------------------------------------------------------- #
# argon2id admin-password hashing (SPEC §6.2, §7.4)
# --------------------------------------------------------------------------- #
def hash_password(password: str) -> str:
    """Hash an admin password with argon2id (offload via to_thread in M3)."""
    return _password_hasher.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """Return ``True`` on match, ``False`` on mismatch (SPEC §7.4).

    argon2's ``verify`` **raises** ``VerifyMismatchError`` on a wrong password
    (it never returns ``False``); this wraps it to a bool. A corrupt/invalid
    stored hash propagates its exception — that is a configuration error, not a
    wrong password. The M3 login path calls this via ``asyncio.to_thread``.
    """
    try:
        return _password_hasher.verify(stored_hash, password)
    except VerifyMismatchError:
        return False


def password_needs_rehash(stored_hash: str) -> bool:
    """Whether ``stored_hash`` should be re-hashed to current params (SPEC §7.4)."""
    return _password_hasher.check_needs_rehash(stored_hash)


# --------------------------------------------------------------------------- #
# Row builders — encapsulate the encrypt/hash so callers never touch raw secrets
# --------------------------------------------------------------------------- #
def build_backend(
    codec: SecretCodec, *, name: str, backend_type: str, config: Mapping[str, Any]
) -> Backend:
    """Build a :class:`Backend` with its shared config KEK-encrypted."""
    return Backend(
        name=name,
        type=backend_type,
        config_encrypted=codec.encrypt_json(config),
    )


def build_domain(
    codec: SecretCodec,
    *,
    zone: str,
    backend_id: int,
    record_name: str,
    he_dynamic_key: str | None = None,
) -> Domain:
    """Build a :class:`Domain`; the HE per-record key (if any) is encrypted.

    Route53 domains pass ``he_dynamic_key=None`` and store ``NULL`` (their
    credentials live on the Backend) — HIGH-7.
    """
    secret = codec.encrypt_text(he_dynamic_key) if he_dynamic_key else None
    return Domain(
        zone=zone,
        backend_id=backend_id,
        record_name=record_name,
        secret_encrypted=secret,
    )


def build_tsig_key(
    codec: SecretCodec, *, name: str, algorithm: str, secret_b64: str
) -> TsigKey:
    """Build a :class:`TsigKey` with the base64 BIND secret KEK-encrypted."""
    return TsigKey(
        name=name,
        algorithm=algorithm,
        secret_encrypted=codec.encrypt_text(secret_b64),
    )


def build_api_token(*, name: str) -> tuple[ApiToken, str]:
    """Build an :class:`ApiToken` (hash-only) and return its one-time plaintext.

    The caller shows the returned plaintext exactly once and then discards it;
    only the row (carrying the SHA-256 hash) is persisted.
    """
    plaintext = generate_token()
    return ApiToken(name=name, token_hash=hash_token(plaintext)), plaintext
