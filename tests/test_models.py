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

"""Model-shape unit tests (T-M2-01, SPEC §6.1/§6.2).

Metadata-level assertions that need no database: table set, the encrypt-vs-hash
column split, the HIGH-7 placement of the HE per-record key on ``Domain`` (never
``Backend``), the append-only ``ChallengeEvent`` shape (no secret columns,
``tsig_key_id`` FK with ``ON DELETE SET NULL``), and timezone-aware timestamps.
Real Postgres round-trips live in the testcontainers suite (T-TEST-12).

Columns are read through ``SQLModel.metadata.tables`` (typed) rather than the
metaclass-injected ``__table__`` attribute, which is invisible to the type
checker.
"""

from __future__ import annotations

from sqlalchemy import DateTime, LargeBinary, Table
from sqlmodel import SQLModel

from astropath.models import AdminCredential


def _table(name: str) -> Table:
    return SQLModel.metadata.tables[name]


def test_all_tables_registered_on_metadata() -> None:
    tables = set(SQLModel.metadata.tables)
    assert {
        "backend",
        "domain",
        "tsigkey",
        "apitoken",
        "challengeevent",
        "admincredential",
    } <= tables


def test_backend_holds_shared_config_and_no_per_record_secret() -> None:
    cols = _table("backend").c
    assert isinstance(cols["config_encrypted"].type, LargeBinary)
    assert cols["config_encrypted"].nullable is False
    # HIGH-7: no per-record secret column on Backend.
    assert "secret_encrypted" not in cols
    assert cols["name"].unique is True
    assert cols["name"].index is True


def test_he_per_record_key_lives_on_domain() -> None:
    cols = _table("domain").c
    # HIGH-7: the HE per-record dynamic key is domain-scoped and nullable
    # (Route53 domains leave it NULL).
    assert isinstance(cols["secret_encrypted"].type, LargeBinary)
    assert cols["secret_encrypted"].nullable is True
    # backend_id references backend.id.
    fk = next(iter(cols["backend_id"].foreign_keys))
    assert fk.column.table.name == "backend"
    assert cols["zone"].unique is True


def test_tsig_secret_is_reversibly_encrypted_not_hashed() -> None:
    cols = _table("tsigkey").c
    assert isinstance(cols["secret_encrypted"].type, LargeBinary)
    assert cols["secret_encrypted"].nullable is False
    # The reversible secret is stored, never a hash (HMAC needs the live value).
    assert "secret_hash" not in cols
    assert cols["name"].unique is True


def test_api_token_is_hash_only() -> None:
    cols = _table("apitoken").c
    assert "token_hash" in cols
    # One-way: no reversible secret column for a token.
    assert "secret_encrypted" not in cols
    assert cols["token_hash"].unique is True


def test_challenge_event_is_secret_free_audit() -> None:
    cols = _table("challengeevent").c
    for expected in (
        "ts",
        "zone",
        "record_name",
        "action",
        "provider",
        "result",
        "latency_ms",
        "tsig_key_id",
        "source",
        "error_detail",
    ):
        assert expected in cols, expected
    # No secret/credential columns leak into the audit trail.
    for forbidden in ("secret_encrypted", "config_encrypted", "token_hash", "password"):
        assert forbidden not in cols


def test_challenge_event_tsig_fk_is_set_null_on_delete() -> None:
    cols = _table("challengeevent").c
    assert cols["tsig_key_id"].nullable is True
    fk = next(iter(cols["tsig_key_id"].foreign_keys))
    assert fk.column.table.name == "tsigkey"
    # Revoking a key must not orphan/break history — SET NULL, not CASCADE.
    assert fk.ondelete == "SET NULL"


def test_admin_credential_is_singleton_row() -> None:
    cols = _table("admincredential").c
    assert cols["id"].primary_key is True
    assert AdminCredential(password_hash="x").id == 1
    assert "password_hash" in cols


def test_timestamps_are_timezone_aware() -> None:
    stamped = {
        "backend": "created_at",
        "domain": "created_at",
        "tsigkey": "created_at",
        "apitoken": "created_at",
        "admincredential": "updated_at",
        "challengeevent": "ts",
    }
    for table_name, column_name in stamped.items():
        column_type = _table(table_name).c[column_name].type
        assert isinstance(column_type, DateTime)
        assert column_type.timezone is True
