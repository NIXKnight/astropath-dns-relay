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

"""RFC2136 UDP + TCP listener (SPEC §3.11).

The ``asyncio.DatagramProtocol`` UDP callback is synchronous and must not await:
it hands each packet off via ``asyncio.create_task``. TCP is mandatory (signed
UPDATEs can exceed 512 bytes) with 2-byte big-endian length framing.

Implemented in T-M1-11 / T-M1-12 / T-M1-13.
"""
