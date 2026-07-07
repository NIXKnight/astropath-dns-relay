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

"""Bootstrap→DB migration unit tests (T-M2-07, SPEC §16.3).

The row-insert logic is checked against a fake session that assigns ids on flush
(so backend↔domain wiring and the encrypt semantics are proven without Docker),
and the CLI's precondition failures are checked for clean, secret-free messages.
The full apply-migrations + insert + serve-from-DB path runs in T-TEST-12.
"""

from __future__ import annotations

import io
from typing import cast

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from astropath.bootstrap import BootstrapConfig, ZoneConfig
from astropath.crypto import Kek, generate_key
from astropath.data_plane.tsig import TsigKeySpec
from astropath.migrate_bootstrap import insert_bootstrap_rows, main
from astropath.models import Backend, Domain, TsigKey
from astropath.store import SecretCodec

_HE_KEY = "he-dynamic-key-123"
_SECRET_B64 = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="


class _FakeSession:
    """Captures added rows; assigns Backend ids on flush like a real INSERT."""

    def __init__(self) -> None:
        self.added: list[object] = []
        self._next_id = 1
        self.committed = False

    def add(self, obj: object) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        for obj in self.added:
            if isinstance(obj, Backend) and obj.id is None:
                obj.id = self._next_id
                self._next_id += 1

    async def commit(self) -> None:
        self.committed = True


def _config() -> BootstrapConfig:
    return BootstrapConfig(
        tsig_keys=[TsigKeySpec("cm-key.", "hmac-sha256", _SECRET_B64)],
        zones=[
            ZoneConfig(
                "a.example.", "hurricane", "_acme-challenge.a.example.", _HE_KEY
            ),
            ZoneConfig(
                "b.example.", "hurricane", "_acme-challenge.b.example.", _HE_KEY
            ),
        ],
    )


async def test_insert_dedups_backend_and_wires_domains() -> None:
    kek = Kek([generate_key()])
    session = _FakeSession()

    counts = await insert_bootstrap_rows(cast(AsyncSession, session), _config(), kek)

    assert (counts.tsig_keys, counts.backends, counts.domains) == (1, 1, 2)
    assert session.committed is True

    backends = [o for o in session.added if isinstance(o, Backend)]
    domains = [o for o in session.added if isinstance(o, Domain)]
    tsig_keys = [o for o in session.added if isinstance(o, TsigKey)]

    # Two hurricane zones share a single backend (deduped by provider type).
    assert len(backends) == 1
    assert backends[0].type == "hurricane"
    # Both domains reference the flushed backend id.
    assert {d.backend_id for d in domains} == {backends[0].id}
    assert len(tsig_keys) == 1


async def test_insert_preserves_encrypted_secret_semantics() -> None:
    kek = Kek([generate_key()])
    codec = SecretCodec(kek)
    session = _FakeSession()

    await insert_bootstrap_rows(cast(AsyncSession, session), _config(), kek)

    tsig = next(o for o in session.added if isinstance(o, TsigKey))
    domain = next(o for o in session.added if isinstance(o, Domain))

    # Ciphertext at rest, but decrypts to the same plaintext under the same KEK.
    assert tsig.secret_encrypted != _SECRET_B64.encode()
    assert codec.decrypt_text(tsig.secret_encrypted) == _SECRET_B64
    assert domain.secret_encrypted is not None
    assert codec.decrypt_text(domain.secret_encrypted) == _HE_KEY


def test_cli_requires_database_dsn(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ASTROPATH_DATABASE_DSN", raising=False)
    monkeypatch.setenv("ASTROPATH_CREDENTIAL_KEK", generate_key())
    out = io.StringIO()

    rc = main(["--bootstrap", "/nonexistent"], out=out)

    assert rc == 1
    assert "ASTROPATH_DATABASE_DSN is not set" in out.getvalue()


def test_cli_requires_kek(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ASTROPATH_DATABASE_DSN", "postgresql+asyncpg://u:p@h/db")
    monkeypatch.delenv("ASTROPATH_CREDENTIAL_KEK", raising=False)
    out = io.StringIO()

    rc = main(["--bootstrap", "/nonexistent"], out=out)

    assert rc == 1
    assert "ASTROPATH_CREDENTIAL_KEK is not set" in out.getvalue()


def test_cli_requires_existing_bootstrap_file(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ASTROPATH_DATABASE_DSN", "postgresql+asyncpg://u:p@h/db")
    kek = generate_key()
    monkeypatch.setenv("ASTROPATH_CREDENTIAL_KEK", kek)
    out = io.StringIO()

    rc = main(["--bootstrap", "/no/such/bootstrap.toml"], out=out)

    assert rc == 1
    message = out.getvalue()
    assert "bootstrap file not found" in message
    assert kek not in message  # the KEK value never leaks into output
