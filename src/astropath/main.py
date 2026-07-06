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

"""Process entrypoint and per-plane supervision (SPEC §2).

``main()`` owns the single asyncio process. It starts the data plane
(RFC2136/TSIG listener) and the management plane (uvicorn/FastAPI) under
*independent* per-plane supervisors — deliberately not ``asyncio.gather`` and
not a top-level ``TaskGroup`` (SPEC §2.1) — owns all shared-resource
startup/teardown, and coordinates graceful shutdown via a shared event.

Implemented in T-M1-23 / T-M1-24.
"""
