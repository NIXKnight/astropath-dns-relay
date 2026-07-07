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

"""Store encrypt-vs-hash unit tests (T-M2-03, SPEC §6.2).

Proves the AC: a DB dump alone yields no plaintext. Reversible secrets survive a
KEK round-trip yet appear only as ciphertext in the column bytes; tokens and
passwords are one-way. Row builders emit encrypted/hashed columns and never carry
the plaintext. All key material is throwaway.
"""

from __future__ import annotations

from astropath.crypto import Kek, generate_key
from astropath.store import (
    SecretCodec,
    build_api_token,
    build_backend,
    build_domain,
    build_tsig_key,
    generate_token,
    hash_password,
    hash_token,
    password_needs_rehash,
    verify_password,
    verify_token,
)

_HE_KEY = "he-dynamic-key-XYZ"
_TSIG_SECRET_B64 = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="


def _codec() -> SecretCodec:
    return SecretCodec(Kek([generate_key()]))


def test_codec_text_round_trip_is_ciphertext_at_rest() -> None:
    codec = _codec()
    token = codec.encrypt_text(_HE_KEY)
    assert isinstance(token, bytes)
    assert _HE_KEY.encode() not in token  # plaintext never appears in ciphertext
    assert codec.decrypt_text(token) == _HE_KEY


def test_codec_json_round_trip() -> None:
    codec = _codec()
    config = {"region": "us-east-1", "hosted_zone_id": "Z123", "access_key": "AKIA"}
    token = codec.encrypt_json(config)
    assert b"AKIA" not in token
    assert codec.decrypt_json(token) == config


def test_token_hash_is_one_way_and_constant_time_verifies() -> None:
    token = generate_token()
    stored = hash_token(token)
    assert token not in stored  # the plaintext is not recoverable from the hash
    assert len(stored) == 64  # sha256 hex
    assert verify_token(token, stored) is True
    assert verify_token("wrong-token", stored) is False


def test_generated_tokens_are_unique_and_high_entropy() -> None:
    tokens = {generate_token() for _ in range(100)}
    assert len(tokens) == 100
    assert all(len(t) >= 40 for t in tokens)


def test_password_hash_is_argon2id_and_verifies() -> None:
    stored = hash_password("correct horse battery staple")
    assert stored.startswith("$argon2id$")
    assert verify_password(stored, "correct horse battery staple") is True
    # Wrong password returns False (argon2 raises VerifyMismatchError internally).
    assert verify_password(stored, "wrong password") is False
    assert password_needs_rehash(stored) is False


def test_build_tsig_key_encrypts_secret() -> None:
    codec = _codec()
    row = build_tsig_key(
        codec, name="cm-key.", algorithm="hmac-sha256", secret_b64=_TSIG_SECRET_B64
    )
    assert row.secret_encrypted is not None
    assert _TSIG_SECRET_B64.encode() not in row.secret_encrypted
    assert codec.decrypt_text(row.secret_encrypted) == _TSIG_SECRET_B64


def test_build_domain_encrypts_he_key_and_allows_null() -> None:
    codec = _codec()
    he = build_domain(
        codec,
        zone="example.com.",
        backend_id=1,
        record_name="_acme-challenge.example.com.",
        he_dynamic_key=_HE_KEY,
    )
    assert he.secret_encrypted is not None
    assert codec.decrypt_text(he.secret_encrypted) == _HE_KEY

    # Route53-style domain leaves the per-record secret NULL (HIGH-7).
    r53 = build_domain(
        codec,
        zone="aws.example.",
        backend_id=2,
        record_name="_acme-challenge.aws.example.",
    )
    assert r53.secret_encrypted is None


def test_build_backend_encrypts_config_json() -> None:
    codec = _codec()
    row = build_backend(
        codec,
        name="he-primary",
        backend_type="hurricane",
        config={"cleanup_placeholder": "cleared"},
    )
    assert b"cleared" not in row.config_encrypted
    assert codec.decrypt_json(row.config_encrypted) == {
        "cleanup_placeholder": "cleared"
    }


def test_build_api_token_returns_hash_row_and_one_time_plaintext() -> None:
    row, plaintext = build_api_token(name="ci-deploy")
    assert row.name == "ci-deploy"
    assert plaintext not in row.token_hash  # only the hash is stored
    assert verify_token(plaintext, row.token_hash) is True
