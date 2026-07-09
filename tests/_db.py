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

"""Shared database test helpers (not a test module — leading underscore).

``apply_migrations`` runs ``alembic upgrade head`` against a container DSN; the
integration suites use it to stand the schema up before seeding rows.
"""

from __future__ import annotations

import os

from alembic import command
from alembic.config import Config


def apply_migrations(dsn: str, alembic_ini: str = "alembic.ini") -> None:
    """Run ``alembic upgrade head`` against ``dsn`` (env-injected in env.py)."""
    os.environ["ASTROPATH_DATABASE_DSN"] = dsn
    command.upgrade(Config(alembic_ini), "head")
