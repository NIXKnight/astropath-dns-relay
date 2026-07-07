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

"""Tests for logging configuration and the redaction filter (T-M0-06).

All secret-shaped values below are obvious non-secret placeholders.
"""

from __future__ import annotations

import logging

import pytest

from astropath.logging_config import REDACTED, RedactionFilter, configure_logging
from astropath.settings import Settings

_PLACEHOLDER = "PLACEHOLDER-NOT-A-REAL-SECRET"


def _settings() -> Settings:
    return Settings(
        database_dsn="postgresql+asyncpg://u:PLACEHOLDER_PW@h:5432/db",
        credential_kek="PLACEHOLDER_KEK",
        admin_password_hash="$argon2id$PLACEHOLDER",
        session_secret="PLACEHOLDER_SESSION",
        log_level="INFO",
        log_format="text",
    )


def test_redaction_filter_redacts_secret_extra() -> None:
    flt = RedactionFilter()
    record = logging.LogRecord(
        "astropath.test", logging.INFO, __file__, 1, "challenge processed", None, None
    )
    record.password = _PLACEHOLDER
    record.session_secret = "another-placeholder"
    record.record_name = "_acme-challenge.example.com"  # not secret-shaped

    assert flt.filter(record) is True
    # dynamically attached `extra=`-style attributes (see RedactionFilter); the
    # stdlib LogRecord type does not declare them, so the reads are type-ignored.
    assert record.password == REDACTED  # type: ignore[attr-defined]
    assert record.session_secret == REDACTED  # type: ignore[attr-defined]
    assert record.record_name == "_acme-challenge.example.com"  # type: ignore[attr-defined]


def test_redaction_filter_redacts_mapping_arg() -> None:
    flt = RedactionFilter()
    # args as a 1-tuple containing a mapping, exactly as logging stores
    # `logger.info("auth %s", {...})`.
    record = logging.LogRecord(
        "astropath.test",
        logging.INFO,
        __file__,
        1,
        "auth %s",
        ({"password": _PLACEHOLDER, "user": "admin"},),
        None,
    )

    flt.filter(record)
    message = record.getMessage()

    assert _PLACEHOLDER not in message
    assert REDACTED in message
    assert "admin" in message  # non-secret value preserved


def test_configure_logging_runs_and_installs_filter() -> None:
    configure_logging(_settings())  # must run without error

    root = logging.getLogger()
    assert root.handlers
    assert any(
        any(isinstance(flt, RedactionFilter) for flt in handler.filters)
        for handler in root.handlers
    ), "no RedactionFilter installed on a root handler"


def test_configure_logging_smoke_redacts_stdout(
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_logging(_settings())

    logging.getLogger("astropath.smoke").info("token seen: %s", {"token": _PLACEHOLDER})

    out = capsys.readouterr().out
    assert _PLACEHOLDER not in out
    assert REDACTED in out


# --------------------------------------------------------------------------- #
# T-M6-02: explicit field-name deny rules + value-shape scrubbing.
# All values below are obvious throwaway placeholders.
# --------------------------------------------------------------------------- #
def _rendered(msg: str, *args: object) -> str:
    record = logging.LogRecord(
        "astropath.test", logging.INFO, __file__, 1, msg, args, None
    )
    RedactionFilter().filter(record)
    return record.getMessage()


def test_scrub_dsn_credentials_keeps_user_and_host() -> None:
    out = _rendered(
        "connecting to %s",
        "postgresql+asyncpg://astropath:PLACEHOLDER_PW@db:5432/astropath",
    )
    assert "PLACEHOLDER_PW" not in out
    assert REDACTED in out
    assert "astropath:" in out and "@db:5432" in out  # shape preserved for debugging


def test_scrub_env_style_secret_assignment() -> None:
    out = _rendered("env dump %s", "ASTROPATH_CREDENTIAL_KEK=abc123def456ghi")
    assert "abc123def456ghi" not in out
    assert "ASTROPATH_CREDENTIAL_KEK=" in out
    assert REDACTED in out


def test_scrub_authorization_bearer_header() -> None:
    out = _rendered("upstream %s", "Authorization: Bearer eyJhbGc.payload.sig")
    assert "eyJhbGc.payload.sig" not in out
    assert REDACTED in out


def test_scrub_x_api_key_header() -> None:
    out = _rendered("headers %s", "X-API-Key: PLACEHOLDER-api-token-value")
    assert "PLACEHOLDER-api-token-value" not in out
    assert REDACTED in out


def test_scrub_bare_bearer_token() -> None:
    out = _rendered("token %s", "Bearer abcd1234efgh5678ijkl")
    assert "abcd1234efgh5678ijkl" not in out
    assert REDACTED in out


def test_scrub_long_base64_key_run() -> None:
    fake_key = "A" * 44  # Fernet-key length; obviously not a real secret
    out = _rendered("kek is %s", fake_key)
    assert fake_key not in out
    assert REDACTED in out


def test_allowlisted_field_names_are_not_redacted() -> None:
    record = logging.LogRecord(
        "astropath.test", logging.INFO, __file__, 1, "routing", None, None
    )
    record.key_name = "cm-key."  # allowlisted: a TSIG key *name* is not a secret
    record.tsig_key_id = "7"  # allowlisted identifier
    RedactionFilter().filter(record)
    assert record.key_name == "cm-key."  # type: ignore[attr-defined]
    assert record.tsig_key_id == "7"  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "field",
    ["password_hash", "he_dynamic_key", "session_secret", "api_key", "cookie"],
)
def test_deny_rule_field_names_are_redacted(field: str) -> None:
    record = logging.LogRecord(
        "astropath.test", logging.INFO, __file__, 1, "auth", None, None
    )
    setattr(record, field, _PLACEHOLDER)
    RedactionFilter().filter(record)
    assert getattr(record, field) == REDACTED


def test_non_secret_string_extra_is_value_scrubbed() -> None:
    # A secret smuggled into an innocuously-named field is still caught (layer 2).
    record = logging.LogRecord(
        "astropath.test", logging.INFO, __file__, 1, "detail", None, None
    )
    record.detail = "dsn=postgresql://u:PLACEHOLDER_PW@h/db"
    RedactionFilter().filter(record)
    assert "PLACEHOLDER_PW" not in record.detail  # type: ignore[attr-defined]
    assert REDACTED in record.detail  # type: ignore[attr-defined]
