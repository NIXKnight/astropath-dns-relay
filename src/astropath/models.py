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

"""SQLModel persistence models (SPEC §6).

``table=True`` models: ``Backend``, ``Domain`` (holds the HE per-record key in
``secret_encrypted``), ``TsigKey``, ``ApiToken``, the append-only
``ChallengeEvent`` audit table, and ``AdminCredential``. ``SQLModel.metadata``
is the Alembic ``target_metadata``.

Implemented in T-M2-01.
"""
