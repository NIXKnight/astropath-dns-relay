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

"""ASGI correlation-id middleware for the management plane (T-M6-03, SPEC §11.4).

A pure-ASGI middleware (deliberately **not** ``BaseHTTPMiddleware``, whose
downstream runs in a separate task where a contextvar set before ``call_next``
would not propagate): it binds a correlation id in the *same* task that calls the
downstream app, so every route/handler log record inherits it, then echoes it on
the ``X-Correlation-ID`` response header for client-side tracing.

An inbound ``X-Correlation-ID`` / ``X-Request-ID`` header is honored so a trace can
span the caller and the gateway, but only after sanitizing it to a safe charset
and length — a client must never be able to inject newlines or secret-shaped
material into the log stream.
"""

from __future__ import annotations

import re

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from astropath.correlation import (
    new_api_correlation_id,
    reset_correlation_id,
    set_correlation_id,
)

__all__ = ["CorrelationIdMiddleware"]

#: Everything outside this set is stripped from a client-supplied id.
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")
_INBOUND_HEADERS = (b"x-correlation-id", b"x-request-id")
_MAX_LEN = 64


def _incoming_correlation_id(scope: Scope) -> str:
    """Return a sanitized client-supplied id, or a fresh one (SPEC §11.4)."""
    for name, value in scope.get("headers", []):
        if name in _INBOUND_HEADERS:
            candidate = _UNSAFE.sub("", value.decode("latin-1", "ignore"))[:_MAX_LEN]
            if candidate:
                return candidate
    return new_api_correlation_id()


class CorrelationIdMiddleware:
    """Bind a correlation id per HTTP request and echo ``X-Correlation-ID``."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        correlation_id = _incoming_correlation_id(scope)
        token = set_correlation_id(correlation_id)

        async def _send(message: Message) -> None:
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message)["X-Correlation-ID"] = correlation_id
            await send(message)

        try:
            await self.app(scope, receive, _send)
        finally:
            reset_correlation_id(token)
