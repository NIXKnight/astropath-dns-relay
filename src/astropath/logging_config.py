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

"""Standard-library logging configuration (SPEC §11.4).

``configure_logging`` installs a single stdout console handler via
``logging.config.dictConfig``, taking the level and format from
:class:`~astropath.settings.Settings`, and attaches a :class:`RedactionFilter`
that masks secret material to ``<REDACTED>`` **before** any handler emits a
record.

Redaction is two-layered (T-M6-02, SPEC §11.4):

1. **Field-name deny rules.** ``extra=`` attributes and mapping-argument keys
   whose name matches an explicit secret-field fragment (``password``, ``secret``,
   ``token``, ``credential``, ``kek``, ``dsn``, ``authorization``, the HE dynamic
   key, the TSIG secret, …) are replaced with ``<REDACTED>``. A small allowlist of
   known non-secret identifiers (``key_name``, ``token_count``, …) is exempt.
2. **Value-shape scrubbing.** The rendered message and string extras are scanned
   for secret-*shaped* substrings — DSN credentials (``scheme://user:pw@host``),
   ``NAME=secret`` env assignments, ``Authorization: Bearer …`` / ``X-API-Key``
   headers, and long base64/base64url runs (Fernet keys, tokens) — and those are
   redacted even when they arrive inside an innocuously-named field. Scrubbing
   errs toward over-redaction: a leaked secret is unacceptable, an over-masked
   public token is merely noisy.

The filter is applied on the handler, so no secret reaches the formatter or
stdout. Correlation-id injection is added by :mod:`astropath.correlation`
(T-M6-03), which layers its own filter alongside this one.
"""

from __future__ import annotations

import json
import logging
import logging.config
import re
from collections.abc import Mapping
from typing import Any

from astropath.settings import Settings

__all__ = ["REDACTED", "RedactionFilter", "JsonFormatter", "configure_logging"]

REDACTED = "<REDACTED>"

# --- Layer 1: field-name deny rules (SPEC §11.4, T-M6-02) ------------------- #
# Secret-shaped field-name fragments, matched case-insensitively with '-' folded
# to '_'. A field whose (normalized) name contains any of these is redacted.
_DENY_FIELD_FRAGMENTS: tuple[str, ...] = (
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
    "x_api_key",
    "cookie",
    "he_dynamic_key",
    "dynamic_key",
    "private_key",
    "tsig_secret",
    "session_secret",
    "password_hash",
    "bearer",
    "passphrase",
)

# Known non-secret identifiers that contain a deny fragment but must NOT be
# redacted (the allow rules). Kept explicit and small.
_ALLOW_FIELDS: frozenset[str] = frozenset(
    {
        "key_name",
        "tsig_key_name",
        "key_id",
        "tsig_key_id",
        "token_count",
        "token_type",
        "public_key",
    }
)

# Standard LogRecord attributes that must never be treated as secret extras.
_RESERVED_ATTRS: frozenset[str] = frozenset(logging.makeLogRecord({}).__dict__) | {
    "message",
    "asctime",
    "taskName",
}

# --- Layer 2: value-shape scrubbing (SPEC §11.4, T-M6-02) ------------------- #
# Applied in order to the rendered message and to string extras. Each pattern
# targets a distinct secret *shape*; the token/credential itself is replaced with
# <REDACTED> while enough context survives to keep the line legible.
_VALUE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # DSN credentials: scheme://user:PASSWORD@host -> keep user, mask password.
    (
        re.compile(r"(?P<pre>://[^\s:/@]+:)[^\s@/]+(?P<at>@)"),
        rf"\g<pre>{REDACTED}\g<at>",
    ),
    # Auth headers / API keys: "Authorization: Bearer x", "X-API-Key: x".
    (
        re.compile(
            r"(?i)(?P<name>\b(?:authorization|proxy-authorization|x-api-key|"
            r"api[_-]?key|cookie|set-cookie))(?P<sep>\s*[:=]\s*)"
            r"(?:bearer\s+|basic\s+)?[^\s,;]+"
        ),
        rf"\g<name>\g<sep>{REDACTED}",
    ),
    # Bare "Bearer <token>" / "Basic <creds>" anywhere in the text.
    (
        re.compile(r"(?i)\b(?P<scheme>bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"),
        rf"\g<scheme> {REDACTED}",
    ),
    # NAME=secret env/kv assignments (secret-shaped key -> mask the value).
    (
        re.compile(
            r"(?i)(?P<key>\b[\w.-]*"
            r"(?:password|passwd|secret|credential|kek|token|api[_-]?key)"
            r"[\w.-]*)(?P<sep>\s*=\s*)[\"']?[^\s\"',;]+[\"']?"
        ),
        rf"\g<key>\g<sep>{REDACTED}",
    ),
    # Long base64 / base64url runs (Fernet keys, hashes, opaque tokens).
    (re.compile(r"[A-Za-z0-9+/_-]{40,}={0,2}"), REDACTED),
)


def _is_secret_key(name: str) -> bool:
    """Return ``True`` when a field name matches the deny rules (not allowlisted)."""
    normalized = name.lower().replace("-", "_")
    if normalized in _ALLOW_FIELDS:
        return False
    return any(fragment in normalized for fragment in _DENY_FIELD_FRAGMENTS)


def _scrub_value(text: str) -> str:
    """Redact secret-*shaped* substrings from free text (SPEC §11.4, T-M6-02)."""
    for pattern, replacement in _VALUE_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _redact_mapping(mapping: Mapping[Any, Any]) -> dict[Any, Any]:
    """Return a copy of ``mapping`` with secret-named string keys redacted."""
    return {
        key: (REDACTED if isinstance(key, str) and _is_secret_key(key) else value)
        for key, value in mapping.items()
    }


class RedactionFilter(logging.Filter):
    """Redact secret material on a log record to ``<REDACTED>`` (SPEC §11.4).

    Runs before the formatter, so nothing secret-shaped reaches stdout:

    (a) ``extra=`` attributes whose *name* matches the deny rules are masked;
        non-secret-named string extras are value-scrubbed;
    (b) secret-named keys inside mapping arguments are masked before rendering;
    (c) the fully-rendered message is value-scrubbed and frozen onto the record
        (``args`` cleared) so the emitted line cannot re-expose a split secret.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        # (a) extra=... attributes attached to the record.
        for key, value in list(record.__dict__.items()):
            if key in _RESERVED_ATTRS or not isinstance(key, str):
                continue
            if _is_secret_key(key):
                if value != REDACTED:
                    setattr(record, key, REDACTED)
            elif isinstance(value, str):
                scrubbed = _scrub_value(value)
                if scrubbed != value:
                    setattr(record, key, scrubbed)

        # (b) mapping arguments, e.g. logger.info("auth %s", {"password": ...}).
        args = record.args
        if isinstance(args, Mapping):
            record.args = _redact_mapping(args)
        elif isinstance(args, tuple):
            record.args = tuple(
                _redact_mapping(item) if isinstance(item, Mapping) else item
                for item in args
            )

        # (c) render, value-scrub, and freeze the message so no handler can
        # re-expose a secret that was split across the format string and args.
        record.msg = _scrub_value(record.getMessage())
        record.args = ()
        return True


class JsonFormatter(logging.Formatter):
    """Minimal single-line JSON log formatter (optional; SPEC §11.4)."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            # Set by CorrelationIdFilter (SPEC §11.4); defaulted for stray records.
            "correlation_id": getattr(record, "correlation_id", None),
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


_TEXT_FORMAT = "%(asctime)s %(levelname)-8s [%(correlation_id)s] %(name)s: %(message)s"


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
            # Correlation runs first (stamps the id), redaction second (scrubs
            # secrets) — both before the formatter, so every emitted line carries
            # the correlation id and no secret (SPEC §11.4).
            "correlation": {"()": "astropath.correlation.CorrelationIdFilter"},
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
                "filters": ["correlation", "redaction"],
                "level": level,
            },
        },
        "root": {"handlers": ["console"], "level": level},
    }
    logging.config.dictConfig(config)
