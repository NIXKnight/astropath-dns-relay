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

"""Startup fail-fast tests (T-M1-26, SPEC §16, LOW-5).

Throwaway secrets only: the KEK is minted per test and the HE/TSIG values are
obvious placeholders (SPEC secret discipline).
"""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from astropath.crypto import Kek, generate_key
from astropath.startup import StartupError, validate_and_load

_TSIG_SECRET = base64.b64encode(b"0123456789abcdef0123456789abcdef").decode()
_HE_KEY = "THROWAWAY-he-dynamic-key"


def _write_bootstrap(
    path: Path,
    kek: Kek,
    *,
    provider: str = "hurricane",
    algorithm: str = "hmac-sha256",
) -> None:
    path.write_text(
        "[listener]\n"
        'host = "127.0.0.1"\n'
        "port = 5353\n\n"
        "[[tsig_keys]]\n"
        'name = "cm-key."\n'
        f'algorithm = "{algorithm}"\n'
        f'secret = "{kek.encrypt_str(_TSIG_SECRET)}"\n\n'
        "[[zones]]\n"
        'zone = "example.com."\n'
        f'provider = "{provider}"\n'
        'record_name = "_acme-challenge.example.com."\n'
        f'he_dynamic_key = "{kek.encrypt_str(_HE_KEY)}"\n',
        encoding="utf-8",
    )


def test_valid_config_returns_kek_and_config(tmp_path: Path) -> None:
    kek_raw = generate_key()
    path = tmp_path / "astropath.bootstrap.toml"
    _write_bootstrap(path, Kek([kek_raw]))

    kek, config = validate_and_load(kek_raw, path)

    assert config.zones[0].provider == "hurricane"
    assert config.tsig_keys[0].secret_b64 == _TSIG_SECRET  # decrypted under the KEK
    assert kek.decrypt_str(Kek([kek_raw]).encrypt_str("ping")) == "ping"


def test_malformed_kek_fails_without_leaking_the_key(tmp_path: Path) -> None:
    bad_kek = "this-is-not-a-fernet-key"
    path = tmp_path / "astropath.bootstrap.toml"
    _write_bootstrap(path, Kek([generate_key()]))

    with pytest.raises(StartupError) as excinfo:
        validate_and_load(bad_kek, path)

    message = str(excinfo.value)
    assert "position 0" in message  # redacted to position...
    assert bad_kek not in message  # ...never the raw key material


def test_missing_kek_fails_fast(tmp_path: Path) -> None:
    with pytest.raises(StartupError, match="credential KEK is not configured"):
        validate_and_load("", tmp_path / "astropath.bootstrap.toml")


def test_missing_bootstrap_file_fails_fast(tmp_path: Path) -> None:
    with pytest.raises(StartupError, match="bootstrap file not found"):
        validate_and_load(generate_key(), tmp_path / "absent.toml")


def test_unconfigured_bootstrap_path_fails_fast() -> None:
    with pytest.raises(StartupError, match="bootstrap path is not configured"):
        validate_and_load(generate_key(), None)


def test_unknown_provider_fails_fast(tmp_path: Path) -> None:
    kek_raw = generate_key()
    path = tmp_path / "astropath.bootstrap.toml"
    _write_bootstrap(path, Kek([kek_raw]), provider="does-not-exist")

    with pytest.raises(StartupError, match="unknown provider 'does-not-exist'"):
        validate_and_load(kek_raw, path)


def test_unsupported_tsig_algorithm_fails_fast(tmp_path: Path) -> None:
    kek_raw = generate_key()
    path = tmp_path / "astropath.bootstrap.toml"
    _write_bootstrap(path, Kek([kek_raw]), algorithm="hmac-bogus-512")

    with pytest.raises(StartupError, match="unsupported algorithm 'hmac-bogus-512'"):
        validate_and_load(kek_raw, path)


def test_wrong_kek_for_ciphertext_fails_fast(tmp_path: Path) -> None:
    path = tmp_path / "astropath.bootstrap.toml"
    _write_bootstrap(path, Kek([generate_key()]))  # encrypted under key A
    other_kek = generate_key()  # a different, valid key B

    with pytest.raises(StartupError, match="do not decrypt under the configured KEK"):
        validate_and_load(other_kek, path)
