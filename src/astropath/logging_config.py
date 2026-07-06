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

"""Standard-library logging configuration (SPEC §11.4).

``configure_logging`` installs a single stdout console handler via
``logging.config.dictConfig``, taking the level and format from
:class:`~astropath.settings.Settings`, and attaches a :class:`RedactionFilter`
that masks known secret-shaped fields to ``<REDACTED>`` before records are
emitted.

This is the M0 placeholder: the filter already redacts known secret-shaped
fields. The full explicit deny-rule set and correlation-id plumbing land in
T-M6-02 / T-M6-03.
"""

from __future__ import annotations

import json
import logging
import logging.config
from collections.abc import Mapping
from typing import Any

from astropath.settings import Settings

__all__ = ["REDACTED", "RedactionFilter", "JsonFormatter", "configure_logging"]

REDACTED = "<REDACTED>"

# Secret-shaped field-name fragments (matched case-insensitively, '-' as '_').
# This is the M0 placeholder deny set; T-M6-02 extends it with the full rules.
_SECRET_FRAGMENTS: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "token",
    "credential",
    "kek",
    "dsn",
    "authorization",
    "api_key",
    "apikey",
    "he_dynamic_key",
    "private_key",
    "tsig_secret",
)

# Standard LogRecord attributes that must never be treated as secret extras.
_RESERVED_ATTRS: frozenset[str] = frozenset(logging.makeLogRecord({}).__dict__) | {
    "message",
    "asctime",
    "taskName",
}


def _is_secret_key(name: str) -> bool:
    """Return ``True`` when a field name looks secret-shaped."""
    normalized = name.lower().replace("-", "_")
    return any(fragment in normalized for fragment in _SECRET_FRAGMENTS)


def _redact_mapping(mapping: Mapping[Any, Any]) -> dict[Any, Any]:
    """Return a copy of ``mapping`` with secret-named string keys redacted."""
    return {
        key: (REDACTED if isinstance(key, str) and _is_secret_key(key) else value)
        for key, value in mapping.items()
    }


class RedactionFilter(logging.Filter):
    """Redact known secret-shaped fields on a log record to ``<REDACTED>``.

    Placeholder scope (T-M0-06): redacts (a) ``extra=`` record attributes whose
    name looks secret and (b) secret-named keys inside mapping log arguments.
    Free-text message-body scrubbing and the full deny-rule set arrive in
    T-M6-02.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        # (a) extra=... attributes attached to the record
        for key, value in list(record.__dict__.items()):
            if key in _RESERVED_ATTRS or not isinstance(key, str):
                continue
            if _is_secret_key(key) and value != REDACTED:
                setattr(record, key, REDACTED)

        # (b) mapping arguments, e.g. logger.info("auth %s", {"password": ...})
        args = record.args
        if isinstance(args, Mapping):
            record.args = _redact_mapping(args)
        elif isinstance(args, tuple):
            record.args = tuple(
                _redact_mapping(item) if isinstance(item, Mapping) else item
                for item in args
            )
        return True


class JsonFormatter(logging.Formatter):
    """Minimal single-line JSON log formatter (optional; SPEC §11.4)."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


_TEXT_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"


def configure_logging(settings: Settings | None = None) -> None:
    """Configure root logging from ``Settings`` (level and format).

    Installs one stdout console handler carrying a :class:`RedactionFilter`.
    When ``settings`` is ``None`` the ``INFO`` / ``text`` defaults are used,
    which is useful for very early startup before configuration is parsed.
    """
    level = (settings.log_level if settings is not None else "INFO").upper()
    log_format = (settings.log_format if settings is not None else "text").lower()
    formatter_name = "json" if log_format == "json" else "text"

    config: dict[str, Any] = {
        "version": 1,
        "disable_existing_loggers": False,
        "filters": {
            "redaction": {"()": f"{__name__}.RedactionFilter"},
        },
        "formatters": {
            "text": {"format": _TEXT_FORMAT},
            "json": {"()": f"{__name__}.JsonFormatter"},
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout",
                "formatter": formatter_name,
                "filters": ["redaction"],
                "level": level,
            },
        },
        "root": {"handlers": ["console"], "level": level},
    }
    logging.config.dictConfig(config)
