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

"""Hurricane Electric dynamic-DNS provider (SPEC §5.7).

Fixed endpoint ``POST https://dyn.dns.he.net/nic/update``; ``good``/``nochg`` are
success, ``badauth``/``nohost`` are hard errors. HE holds one value per dynamic
record (``supports_multivalue=False``) and cannot delete
(``supports_delete=False``; ``cleanup()`` overwrites a placeholder). The
per-record dynamic key is domain-scoped.

Implemented in T-M1-18.
"""
