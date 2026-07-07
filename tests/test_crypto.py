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

"""KEK / MultiFernet crypto unit tests (T-M1-20, SPEC §7).

Proves the T-M1-20 acceptance criteria: encrypt/decrypt round-trips; old-key
ciphertext still decrypts after a new key is prepended; no-ttl decrypt of an
aged token; ``rotate`` re-encrypts under the primary. Also covers the fail-fast
validation (T-M1-26). All keys are generated fresh and discarded.
"""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from astropath.crypto import InvalidToken, Kek, KekError, generate_key, parse_keylist


def test_encrypt_decrypt_round_trip() -> None:
    kek = Kek([generate_key()])
    token = kek.encrypt(b"a-tsig-secret")
    assert token != b"a-tsig-secret"
    assert kek.decrypt(token) == b"a-tsig-secret"


def test_encrypt_decrypt_str_round_trip() -> None:
    kek = Kek([generate_key()])
    token = kek.encrypt_str("he-dynamic-key-value")
    assert kek.decrypt_str(token) == "he-dynamic-key-value"


def test_old_key_ciphertext_decrypts_after_prepend() -> None:
    """Rotation semantics: prepend a new primary, still read old-key tokens."""
    old_key = generate_key()
    old = Kek([old_key])
    token = old.encrypt(b"aged-secret")

    new_key = generate_key()
    rotated_kek = Kek([new_key, old_key])  # new primary prepended
    assert rotated_kek.decrypt(token) == b"aged-secret"


def test_rotate_re_encrypts_under_primary() -> None:
    old_key = generate_key()
    new_key = generate_key()
    token = Kek([old_key]).encrypt(b"secret")

    rotated_kek = Kek([new_key, old_key])
    migrated = rotated_kek.rotate(token)
    assert migrated != token
    # Migrated ciphertext decrypts under the new primary alone.
    assert Kek([new_key]).decrypt(migrated) == b"secret"


def test_no_ttl_decrypt_does_not_expire() -> None:
    """At-rest decrypt passes no ttl, so an old token never spuriously fails."""
    key = generate_key()
    token = Kek([key]).encrypt(b"stored-long-ago")
    assert Kek([key]).decrypt(token) == b"stored-long-ago"


# --------------------------------------------------------------------------- #
# T-TEST-08 gap-fill: the round-trip / cross-keylist / old-key-after-prepend
# clauses are proven above. The two cases below make the timestamp and aged-
# token clauses meaningful — the existing rotate/no-ttl tests use fresh tokens,
# which cannot distinguish "preserved" from "restamped now". A token is stamped
# far in the past with Fernet.encrypt_at_time so the assertions are decisive.
# --------------------------------------------------------------------------- #

_LONG_AGO = 1_000_000_000  # 2001-09-09 UTC — decisively older than any test run


def test_rotate_preserves_creation_timestamp() -> None:
    """AC 'rotate() preserves timestamp': a token stamped long ago keeps that
    exact creation time after rotation under a new primary (not restamped now)."""
    old_key = generate_key()
    new_key = generate_key()
    token = Fernet(old_key).encrypt_at_time(b"aged-secret", _LONG_AGO)

    migrated = Kek([new_key, old_key]).rotate(token)

    # extract_timestamp reads the (unverified) creation time; it stays _LONG_AGO.
    assert Fernet(new_key).extract_timestamp(migrated) == _LONG_AGO
    assert migrated != token  # genuinely re-encrypted under the new primary
    assert Kek([new_key]).decrypt(migrated) == b"aged-secret"


def test_aged_token_decrypts_without_ttl_but_would_fail_under_ttl() -> None:
    """AC 'no-ttl decrypt of aged token': Kek.decrypt passes no ttl, so a token
    stamped long ago still decrypts; the identical token WOULD raise InvalidToken
    once a ttl is enforced (SPEC §7.1 — why the at-rest path omits ttl)."""
    key = generate_key()
    token = Fernet(key).encrypt_at_time(b"stored-long-ago", _LONG_AGO)

    # No ttl (the Kek at-rest path) -> the aged token is accepted.
    assert Kek([key]).decrypt(token) == b"stored-long-ago"

    # Contrast: the same aged token is rejected the moment a ttl is applied.
    with pytest.raises(InvalidToken):
        Fernet(key).decrypt(token, ttl=60)


def test_decrypt_rejects_foreign_token() -> None:
    token = Kek([generate_key()]).encrypt(b"secret")
    with pytest.raises(InvalidToken):
        Kek([generate_key()]).decrypt(token)  # unrelated key


def test_parse_keylist_splits_on_comma_and_whitespace() -> None:
    k1, k2, k3 = generate_key(), generate_key(), generate_key()
    assert parse_keylist(f"{k1},{k2}") == [k1, k2]
    assert parse_keylist(f"  {k1}   {k2} \n {k3} ") == [k1, k2, k3]
    assert parse_keylist("") == []


def test_empty_keylist_fails_fast() -> None:
    with pytest.raises(KekError):
        Kek([])


def test_invalid_key_fails_fast_without_leaking_value() -> None:
    secret_like = "NOT-A-VALID-FERNET-KEY-should-not-appear"
    with pytest.raises(KekError) as exc:
        Kek([secret_like])
    assert secret_like not in str(exc.value)
    assert "position 0" in str(exc.value)
