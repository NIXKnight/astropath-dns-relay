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
