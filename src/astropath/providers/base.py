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

"""Provider ABC and the module-level registry (SPEC §5.1, §5.2).

The ``Provider`` abstract base class defines ``config_schema()``,
``from_config()``, async ``present``/``cleanup``/``validate``, and the
``supports_multivalue`` / ``supports_delete`` class flags. ``REGISTRY`` maps a
provider ``type`` string to its ``Provider`` subclass.

Implemented in T-M1-17.
"""
