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

"""KEK rotation + backup/restore runbook (T-M2-08, SPEC §7.3, HIGH-6).

The KEK is a **MultiFernet keylist** (primary first). ``MultiFernet.decrypt``
reads any key in the list, so rotation needs no schema/version column — a new key
is prepended and old ciphertext keeps decrypting.
:func:`rotate_stored_secrets` performs the optional bulk migration step, calling
``Kek.rotate`` on every stored ciphertext (re-encrypt under the primary key while
preserving the original creation timestamp).

Rotation runbook (SPEC §7.3)
----------------------------
1. Generate a new Fernet key (``astropath.crypto.generate_key`` /
   ``astropath-bootstrap gen-kek``).
2. **Prepend** it to ``ASTROPATH_CREDENTIAL_KEK`` (ordered list, primary first);
   keep the retired key in the list. Store the keylist ansible-vault'd.
3. Rolling-restart the service. ``MultiFernet([new, old])`` now writes new-key
   ciphertext and still reads old-key ciphertext, so the service is correct
   before any bulk migration runs.
4. Run the bulk pass — :func:`rotate_stored_secrets` — to re-encrypt every stored
   secret under the new primary. It is idempotent and safe to re-run.
5. Once every ciphertext is migrated and verified, **drop the retired key** from
   ``ASTROPATH_CREDENTIAL_KEK`` and restart.

Backup / restore (SPEC §7.3, §6.2)
----------------------------------
- **Backup** = the Postgres dump (ciphertext-only) **plus** the KEK keylist,
  stored **separately** (ansible-vault'd). Restoring needs both.
- A database dump **alone restores nothing sensitive**: provider/TSIG/HE secrets
  are KEK-encrypted (need the keylist) and tokens/passwords are one-way hashed
  (unrecoverable). This is the encrypt-vs-hash guarantee proven in the store
  tests (T-M2-03).

OpenBao seam (future)
---------------------
A later Alembic revision may store only *references* in the encrypted columns and
fetch the real credentials from OpenBao at dispatch; the crypto layer then becomes
a thin adapter. Not in v1.

Secret discipline: only opaque ciphertext is read/written here; no plaintext is
decrypted, logged, or returned.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from astropath.crypto import Kek
from astropath.models import Backend, Domain, TsigKey

__all__ = ["RotationCounts", "rotate_stored_secrets"]


@dataclass(frozen=True)
class RotationCounts:
    """How many ciphertext columns were re-encrypted under the new primary."""

    backends: int
    domains: int
    tsig_keys: int

    @property
    def total(self) -> int:
        return self.backends + self.domains + self.tsig_keys


async def rotate_stored_secrets(session: AsyncSession, kek: Kek) -> RotationCounts:
    """Re-encrypt every stored ciphertext under the KEK's primary key (SPEC §7.3).

    Operates purely on opaque Fernet tokens — no plaintext is decrypted. Domains
    with a ``NULL`` per-record secret (e.g. Route53) are skipped. Call with a
    ``Kek`` whose keylist contains both the new primary and the retiring key so
    ``rotate`` can read old ciphertext and rewrite it new. The caller's session is
    committed here.
    """
    backends = (await session.execute(select(Backend))).scalars().all()
    for backend in backends:
        backend.config_encrypted = kek.rotate(backend.config_encrypted)

    domains = (await session.execute(select(Domain))).scalars().all()
    rotated_domains = 0
    for domain in domains:
        if domain.secret_encrypted is not None:
            domain.secret_encrypted = kek.rotate(domain.secret_encrypted)
            rotated_domains += 1

    tsig_keys = (await session.execute(select(TsigKey))).scalars().all()
    for tsig_key in tsig_keys:
        tsig_key.secret_encrypted = kek.rotate(tsig_key.secret_encrypted)

    await session.commit()
    return RotationCounts(
        backends=len(backends),
        domains=rotated_domains,
        tsig_keys=len(tsig_keys),
    )
