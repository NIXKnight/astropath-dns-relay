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

"""KEK / direct key encryption for credentials at rest (SPEC §7).

Fernet + ``MultiFernet`` for KEK rotation: encrypt with the primary key, decrypt
across the keylist, ``rotate()`` for lazy re-encryption, and at-rest decrypt with
no ``ttl``. This is *direct* key encryption, deliberately not called "envelope"
encryption (SPEC §7.2). The optional AES-256-GCM path is per SPEC §7.2.

Implemented in T-M1-20.
"""
