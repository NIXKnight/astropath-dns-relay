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

"""CSRF origin/referer protection for cookie-authenticated writes (SPEC §8.4).

Cross-site request forgery only bites **ambient** credentials — the session cookie
a browser attaches automatically. So mutating ``/api/v1`` requests are origin-
checked **unless** they carry an ``X-API-Key`` header (a non-browser client with no
ambient credential is exempt, SPEC §8.4). The allowed origin is the configured
``astropath.<domain>``; a missing or mismatched ``Origin`` (falling back to the
``Referer`` origin) is rejected with 403. Safe methods and non-API paths pass
through. When no origin is configured the check is disabled (single-node dev).
"""

from __future__ import annotations

from urllib.parse import urlsplit

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

__all__ = ["CsrfOriginMiddleware"]

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})


def _origin_of(url: str) -> str | None:
    """Return the ``scheme://host[:port]`` origin of ``url`` (or ``None``)."""
    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        return None
    return f"{parts.scheme}://{parts.netloc}"


class CsrfOriginMiddleware(BaseHTTPMiddleware):
    """Reject cross-origin cookie-authenticated mutations (SPEC §8.4)."""

    def __init__(
        self,
        app: object,
        *,
        allowed_origin: str | None,
        protected_prefix: str = "/api/v1",
    ) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self._allowed = allowed_origin
        self._prefix = protected_prefix

    def _needs_check(self, request: Request) -> bool:
        if self._allowed is None:
            return False  # origin check disabled (unconfigured)
        if request.method in _SAFE_METHODS:
            return False
        if not request.url.path.startswith(self._prefix):
            return False
        # A token client carries no ambient credential -> not a CSRF target.
        return "x-api-key" not in request.headers

    def _origin_allowed(self, request: Request) -> bool:
        origin = request.headers.get("origin")
        if origin is None:
            referer = request.headers.get("referer")
            origin = _origin_of(referer) if referer else None
        return origin is not None and origin == self._allowed

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if self._needs_check(request) and not self._origin_allowed(request):
            return JSONResponse({"detail": "origin check failed"}, status_code=403)
        return await call_next(request)
