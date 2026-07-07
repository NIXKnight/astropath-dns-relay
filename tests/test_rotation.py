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

"""KEK-rotation unit tests (T-M2-08, SPEC §7.3, HIGH-6).

The bulk-rotate logic is checked against a fake session routing ``select(Model)``
by entity: every stored ciphertext is re-encrypted under the new primary and then
decrypts under the new key alone, while a ``NULL`` domain secret is skipped. The
runbook is validated end-to-end against real Postgres in T-TEST-12.
"""

from __future__ import annotations

from typing import Any, cast

from sqlalchemy.ext.asyncio import AsyncSession

from astropath.crypto import Kek, generate_key
from astropath.models import Backend, Domain, TsigKey
from astropath.rotation import RotationCounts, rotate_stored_secrets
from astropath.store import SecretCodec, build_backend, build_domain, build_tsig_key

_SECRET_B64 = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
_HE_KEY = "he-dynamic-key-abc"


class _FakeResult:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def scalars(self) -> _FakeResult:
        return self

    def all(self) -> list[Any]:
        return self._rows


class _FakeSession:
    """Routes ``execute(select(Model))`` to a per-model row list."""

    def __init__(self, rows_by_model: dict[type, list[Any]]) -> None:
        self._rows = rows_by_model
        self.committed = False

    async def execute(self, stmt: Any) -> _FakeResult:
        entity = stmt.column_descriptions[0]["entity"]
        return _FakeResult(self._rows.get(entity, []))

    async def commit(self) -> None:
        self.committed = True


def test_rotation_counts_total() -> None:
    assert RotationCounts(backends=2, domains=3, tsig_keys=1).total == 6


async def test_rotate_migrates_all_ciphertext_to_new_primary() -> None:
    old_key = generate_key()
    old = SecretCodec(Kek([old_key]))

    backend = build_backend(
        old, name="hurricane", backend_type="hurricane", config={"k": "v"}
    )
    domain = build_domain(
        old,
        zone="a.example.",
        backend_id=1,
        record_name="_acme-challenge.a.example.",
        he_dynamic_key=_HE_KEY,
    )
    keyless_domain = build_domain(
        old, zone="b.example.", backend_id=1, record_name="_acme-challenge.b.example."
    )
    tsig = build_tsig_key(
        old, name="cm-key.", algorithm="hmac-sha256", secret_b64=_SECRET_B64
    )

    new_key = generate_key()
    rotate_kek = Kek([new_key, old_key])  # new primary prepended, old retained
    session = _FakeSession(
        {
            Backend: [backend],
            Domain: [domain, keyless_domain],
            TsigKey: [tsig],
        }
    )

    counts = await rotate_stored_secrets(cast(AsyncSession, session), rotate_kek)

    assert (counts.backends, counts.domains, counts.tsig_keys) == (1, 1, 1)
    assert session.committed is True

    # Every rotated ciphertext now decrypts under the NEW key alone.
    new_only = SecretCodec(Kek([new_key]))
    assert new_only.decrypt_json(backend.config_encrypted) == {"k": "v"}
    assert domain.secret_encrypted is not None
    assert new_only.decrypt_text(domain.secret_encrypted) == _HE_KEY
    assert new_only.decrypt_text(tsig.secret_encrypted) == _SECRET_B64
    # The keyless domain is untouched.
    assert keyless_domain.secret_encrypted is None
