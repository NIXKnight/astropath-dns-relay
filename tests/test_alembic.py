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

"""Alembic scaffold unit tests (T-M2-04, SPEC §12.1).

Docker-free checks on the migration chain: revision 1 is the single head and the
baseline (``down_revision is None``), and the env's ``target_metadata`` covers
every model table. Applying the migration against real Postgres (``upgrade head``
+ zero-drift ``check``) is exercised in the testcontainers suite (T-TEST-12).
"""

from __future__ import annotations

from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlmodel import SQLModel

import astropath.models  # noqa: F401  (register tables on SQLModel.metadata)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_ALEMBIC_INI = _PROJECT_ROOT / "alembic.ini"


def _script() -> ScriptDirectory:
    return ScriptDirectory.from_config(Config(str(_ALEMBIC_INI)))


def test_revision_one_is_the_single_head() -> None:
    assert _script().get_heads() == ["0001"]


def test_revision_one_is_the_baseline() -> None:
    revision = _script().get_revision("0001")
    assert revision.down_revision is None


def test_target_metadata_covers_every_model_table() -> None:
    # env.py sets target_metadata = SQLModel.metadata; the six models must be on
    # it so autogenerate/upgrade build the full schema.
    tables = set(SQLModel.metadata.tables)
    assert {
        "backend",
        "domain",
        "tsigkey",
        "apitoken",
        "challengeevent",
        "admincredential",
    } <= tables


def test_alembic_ini_leaves_url_blank_for_env_injection() -> None:
    # The DSN is injected from ASTROPATH_DATABASE_DSN by env.py; the ini URL is
    # intentionally blank so CI/prod need not edit the file.
    url = Config(str(_ALEMBIC_INI)).get_main_option("sqlalchemy.url")
    assert not url
