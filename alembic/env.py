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

"""Alembic async migration environment (SPEC §12.1, MED-3).

The schema is owned by Alembic from M2 onward; revision 1 is the DB-landing
baseline. ``target_metadata`` is ``SQLModel.metadata`` — importing
``astropath.models`` registers every ``table=True`` model on it. The connection
URL comes from ``ASTROPATH_DATABASE_DSN`` (a ``postgresql+asyncpg://`` DSN) so CI
testcontainers and production inject it without editing ``alembic.ini``. The URL
is set on the engine section directly (not via ``set_main_option``) to avoid
configparser ``%``-interpolation on DSN passwords.
"""

import asyncio
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config
from sqlmodel import SQLModel

import astropath.models  # noqa: F401  (registers every table on SQLModel.metadata)

# Alembic Config object providing access to the .ini file values.
config = context.config

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Autogenerate targets SQLModel.metadata (a SQLAlchemy MetaData, SPEC §12.1).
target_metadata = SQLModel.metadata

# Prefer the runtime DSN from the environment (CI/prod inject it).
_DSN = os.environ.get("ASTROPATH_DATABASE_DSN")


def _engine_section() -> dict[str, str]:
    """Return the engine config section with the DSN overridden from env."""
    section = config.get_section(config.config_ini_section, {})
    if _DSN:
        section["sqlalchemy.url"] = _DSN
    return section


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (emit SQL without a DBAPI connection)."""
    url = _DSN or config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    """Configure the context on a live connection and run migrations."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Create an async engine and run migrations via ``connection.run_sync``."""
    connectable = async_engine_from_config(
        _engine_section(),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
