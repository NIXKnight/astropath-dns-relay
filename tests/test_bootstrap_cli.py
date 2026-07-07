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

"""astropath-bootstrap CLI tests (T-M1-22, SPEC §16.1)."""

from __future__ import annotations

import base64
import io
from pathlib import Path

import dns.tsig
import pytest

from astropath.bootstrap import load_bootstrap, main
from astropath.crypto import Kek, generate_key


def _run(*argv: str) -> str:
    out = io.StringIO()
    assert main(list(argv), out=out) == 0
    return out.getvalue()


def test_gen_tsig_emits_base64_bind_secret_once() -> None:
    output = _run("gen-tsig", "--name", "cm-key.")

    assert "key_name: cm-key." in output
    assert "algorithm: hmac-sha256" in output
    assert output.count("secret:") == 1  # shown exactly once

    secret_line = next(
        line for line in output.splitlines() if line.startswith("secret:")
    )
    secret_b64 = secret_line.split(": ", 1)[1]
    assert len(base64.b64decode(secret_b64)) == 32  # 32-byte HMAC key, BIND form


def test_algorithm_text_matches_dnspython() -> None:
    # T-M1-22 AC: the dashless-dot-less 'hmac-sha256' is the algorithm form used.
    assert dns.tsig.HMAC_SHA256.to_text(omit_final_dot=True) == "hmac-sha256"


def test_gen_kek_emits_valid_fernet_key() -> None:
    key = _run("gen-kek").strip()
    Kek([key])  # constructs without error -> valid Fernet key


def test_secret_yaml_uses_stringdata_not_data() -> None:
    output = _run("secret-yaml", "--secret", "PLACEHOLDER-BIND-SECRET")

    assert "stringData:" in output
    assert "tsig-secret-key: PLACEHOLDER-BIND-SECRET" in output
    assert "namespace: cert-manager" in output
    assert "\n  data:" not in output  # never hand-encode .data (no double-base64)


def test_init_writes_loadable_encrypted_bootstrap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    kek_key = generate_key()
    monkeypatch.setenv("ASTROPATH_CREDENTIAL_KEK", kek_key)
    path = tmp_path / "astropath.bootstrap.toml"

    output = _run(
        "init",
        "--output",
        str(path),
        "--name",
        "cm-key.",
        "--zone",
        "example.com.",
        "--record-name",
        "_acme-challenge.example.com.",
        "--he-key",
        "THROWAWAY-he-key",
        "--port",
        "5353",
    )

    # The plaintext TSIG secret is revealed once in stdout...
    secret_line = next(line for line in output.splitlines() if "secret (base64" in line)
    revealed = secret_line.rsplit(": ", 1)[1]
    file_text = path.read_text(encoding="utf-8")
    # ...but is stored encrypted in the file (plaintext never written to disk).
    assert revealed not in file_text
    assert "THROWAWAY-he-key" not in file_text

    # The written file loads and decrypts under the same KEK.
    config = load_bootstrap(path, Kek([kek_key]))
    assert config.tsig_keys[0].name == "cm-key."
    assert config.tsig_keys[0].secret_b64 == revealed
    assert config.zones[0].zone == "example.com."
    assert config.zones[0].he_dynamic_key == "THROWAWAY-he-key"
    assert config.listener_port == 5353


def test_init_without_kek_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ASTROPATH_CREDENTIAL_KEK", raising=False)
    from astropath.bootstrap import BootstrapError

    with pytest.raises(BootstrapError):
        main(
            [
                "init",
                "--output",
                str(tmp_path / "b.toml"),
                "--zone",
                "example.com.",
                "--record-name",
                "_acme-challenge.example.com.",
            ],
            out=io.StringIO(),
        )
