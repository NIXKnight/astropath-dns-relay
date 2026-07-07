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

"""Correlation-id propagation across the data and management planes (T-M6-03).

A single :class:`~contextvars.ContextVar` threads one id through an inbound DNS
UPDATE's whole lifecycle — parse, auth gate, dispatch, provider call, audit write
— and, separately, through one management-API request. Because a context is
copied into every :func:`asyncio.create_task` child at creation, the UDP hand-off
(SPEC §3.11) and each awaited provider/DB call inherit the id automatically,
without threading an argument through every call site.

The id is a short, non-secret token (``dns-<reqid>-<rand>`` for a DNS message,
``api-<rand>`` for an API request). It surfaces on every log record via
:class:`CorrelationIdFilter` (wired in :mod:`astropath.logging_config`) and on the
API response ``X-Correlation-ID`` header, so a stuck challenge is traceable end to
end: the DNS request id + source IP → the challenge's correlated log records → its
``ChallengeEvent`` audit row (SPEC §6.1, §11.4). The audit linkage reuses the
existing ``ChallengeEvent`` fields (source, zone, ts) — no new column.

Secret discipline: the id never encodes secret material; a client-supplied inbound
correlation header is sanitized to a safe charset before use (see
:mod:`astropath.api.correlation_mw`).
"""

from __future__ import annotations

import contextlib
import logging
import secrets
from collections.abc import Iterator
from contextvars import ContextVar, Token

__all__ = [
    "CorrelationIdFilter",
    "correlation_scope",
    "get_correlation_id",
    "new_api_correlation_id",
    "new_dns_correlation_id",
    "reset_correlation_id",
    "set_correlation_id",
]

#: The active correlation id, or ``None`` outside any correlated span.
_correlation_id: ContextVar[str | None] = ContextVar(
    "astropath_correlation_id", default=None
)

#: Rendered on log records when no correlation id is bound (keeps the log column
#: aligned outside a correlated span, e.g. during startup).
UNSET = "-"


def get_correlation_id() -> str | None:
    """Return the correlation id bound to the current context (or ``None``)."""
    return _correlation_id.get()


def set_correlation_id(value: str) -> Token[str | None]:
    """Bind ``value`` as the current correlation id; return the reset token."""
    return _correlation_id.set(value)


def reset_correlation_id(token: Token[str | None]) -> None:
    """Restore the correlation id to what it was before ``token`` was issued."""
    _correlation_id.reset(token)


def new_dns_correlation_id(request_id: int) -> str:
    """Mint a correlation id embedding the 16-bit DNS request id (SPEC §11.4)."""
    return f"dns-{request_id & 0xFFFF:04x}-{secrets.token_hex(4)}"


def new_api_correlation_id() -> str:
    """Mint a correlation id for one management-API request (SPEC §11.4)."""
    return f"api-{secrets.token_hex(8)}"


@contextlib.contextmanager
def correlation_scope(value: str) -> Iterator[str]:
    """Bind ``value`` for the duration of the ``with`` block, then restore.

    Setting a contextvar inside an ``async`` function persists across ``await``
    points in the same task, so wrapping :func:`astropath.data_plane.protocol.
    handle_query` in this scope correlates the whole dispatch chain.
    """
    token = _correlation_id.set(value)
    try:
        yield value
    finally:
        _correlation_id.reset(token)


class CorrelationIdFilter(logging.Filter):
    """Stamp the active correlation id onto every log record (SPEC §11.4).

    Installed on the console handler so ``%(correlation_id)s`` (text) / the
    ``correlation_id`` JSON field is always populated — bound id or ``"-"``.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        record.correlation_id = _correlation_id.get() or UNSET
        return True
