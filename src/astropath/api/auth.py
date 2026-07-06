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

"""Management-plane authentication (SPEC §8).

``require_admin`` accepts either a signed session cookie or an ``X-API-Key``
header (both extractors use ``auto_error=False``) and raises
``HTTPException(401)`` itself when neither is valid. argon2 verification is
offloaded via ``asyncio.to_thread``.

Implemented in T-M3-02 / T-M3-04.
"""
