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

"""Tests for the pydantic-settings ``Settings`` model (T-M0-05).

All values below are obvious non-secret placeholders; no real secret exists in
this repository (SPEC secret discipline).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from astropath.settings import Settings

_SECRET_ENV = {
    "ASTROPATH_DATABASE_DSN": "postgresql+asyncpg://astropath:PLACEHOLDER_PW@localhost:5432/astropath",
    "ASTROPATH_CREDENTIAL_KEK": "PLACEHOLDER_FERNET_KEY_PRIMARY",
    "ASTROPATH_ADMIN_PASSWORD_HASH": "$argon2id$v=19$m=65536,t=3,p=4$PLACEHOLDERSALT$PLACEHOLDERHASH",
    "ASTROPATH_SESSION_SECRET": "PLACEHOLDER_SESSION_SIGNING_SECRET",
}


def _set_secret_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in _SECRET_ENV.items():
        monkeypatch.setenv(name, value)


def test_env_vars_load_with_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_secret_env(monkeypatch)
    monkeypatch.setenv("ASTROPATH_DNS_PORT", "5353")
    monkeypatch.setenv("ASTROPATH_LOG_LEVEL", "DEBUG")

    settings = Settings()

    assert settings.database_dsn.get_secret_value() == _SECRET_ENV["ASTROPATH_DATABASE_DSN"]
    assert settings.credential_kek.get_secret_value() == _SECRET_ENV["ASTROPATH_CREDENTIAL_KEK"]
    assert settings.dns_port == 5353  # int coercion from env string
    assert settings.log_level == "DEBUG"
    # unset non-secret config keeps its default
    assert settings.http_port == 8080
    assert settings.forwarded_allow_ips == "127.0.0.1"


def test_env_is_case_insensitive(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_secret_env(monkeypatch)
    monkeypatch.setenv("astropath_http_port", "9000")  # lowercase name

    settings = Settings()

    assert settings.http_port == 9000


def test_secretstr_never_renders(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_secret_env(monkeypatch)
    settings = Settings()

    rendered = "\n".join(
        [
            repr(settings),
            str(settings),
            repr(settings.database_dsn),
            str(settings.session_secret),
            str(settings.model_dump()),
            settings.model_dump_json(),
        ]
    )

    for secret_value in _SECRET_ENV.values():
        assert secret_value not in rendered, "SecretStr value leaked into a rendering"

    # masking marker present; real value retrievable only via get_secret_value()
    assert "**********" in repr(settings.session_secret)
    assert settings.session_secret.get_secret_value() == _SECRET_ENV["ASTROPATH_SESSION_SECRET"]


def test_missing_required_secret_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _SECRET_ENV:
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(ValidationError):
        Settings()
