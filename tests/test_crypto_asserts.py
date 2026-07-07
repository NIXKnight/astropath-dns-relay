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

"""Crypto / argon2 build-time asserts (T-TEST-16, SPEC §7, §18.1).

Pins the pinned-version behaviour of the chosen KEK scheme (Fernet +
``MultiFernet``, SPEC §7.1) and records the AES-256-GCM alternative's nonce
bound (SPEC §7.2). All key material is generated fresh and thrown away; no
secret is persisted.
"""

from __future__ import annotations

import base64

from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def test_fernet_key_is_128_bit_split_16_plus_16() -> None:
    """A Fernet key is 32 raw bytes = 16-byte HMAC key + 16-byte AES-128 key.

    Fernet is AES-128-CBC + HMAC-SHA256 (SPEC §7.1). The 44-char urlsafe-base64
    key decodes to exactly 32 bytes; per the Fernet spec the first 16 are the
    HMAC signing key and the last 16 the AES key.
    """
    key = Fernet.generate_key()
    assert len(key) == 44  # urlsafe base64 of 32 bytes
    raw = base64.urlsafe_b64decode(key)
    assert len(raw) == 32
    signing_key, aes_key = raw[:16], raw[16:]
    assert len(signing_key) == 16
    assert len(aes_key) == 16


def test_multifernet_and_rotate_present() -> None:
    mf = MultiFernet([Fernet(Fernet.generate_key())])
    assert hasattr(mf, "encrypt")
    assert hasattr(mf, "decrypt")
    assert hasattr(mf, "rotate")


def test_multifernet_encrypts_with_first_decrypts_across_list() -> None:
    new = Fernet(Fernet.generate_key())
    old = Fernet(Fernet.generate_key())
    old_token = old.encrypt(b"aged-secret")

    mf = MultiFernet([new, old])  # primary first
    fresh = mf.encrypt(b"fresh-secret")

    # primary decrypts what it wrote
    assert new.decrypt(fresh) == b"fresh-secret"
    # list decrypt still reads the old-key token (no key/version column needed)
    assert mf.decrypt(old_token) == b"aged-secret"


def test_fernet_decrypt_without_ttl_never_expires_aged_tokens() -> None:
    """At-rest decrypt uses NO ``ttl`` (SPEC §7.1) so aged tokens still read."""
    f = Fernet(Fernet.generate_key())
    token = f.encrypt(b"stored-long-ago")
    assert f.decrypt(token) == b"stored-long-ago"  # ttl defaults to None


def test_aesgcm_alternative_uses_96_bit_nonce() -> None:
    """AES-256-GCM alternative (SPEC §7.2): 12-byte (96-bit) nonce.

    Random-96-bit-nonce safety bound ~2^32 messages per key (NIST SP 800-38D);
    far above astropath write volume. Documented here since Fernet is the chosen
    default and AES-256-GCM ships only if AES-256 is later mandated.
    """
    key = AESGCM.generate_key(bit_length=256)
    assert len(key) == 32  # 256-bit
    aead = AESGCM(key)
    nonce = b"\x00" * 12  # 96-bit
    blob = aead.encrypt(nonce, b"plaintext", b"assoc-id")
    assert aead.decrypt(nonce, blob, b"assoc-id") == b"plaintext"


def test_argon2_verify_raises_not_returns_false() -> None:
    """argon2 ``verify`` raises on mismatch, never returns ``False`` (SPEC §7.4)."""
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError

    ph = PasswordHasher()
    digest = ph.hash("correct-horse")
    assert ph.verify(digest, "correct-horse") is True
    raised = False
    try:
        ph.verify(digest, "wrong-password")
    except VerifyMismatchError:
        raised = True
    assert raised, "verify() must raise VerifyMismatchError, not return False"
