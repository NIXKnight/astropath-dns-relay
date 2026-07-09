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

"""KEK startup fail-fast tests (T-M6-10, SPEC §11.3, LOW-5).

The KEK is the one precondition that can be checked without any IO: it is always
required (it decrypts the DB-stored provider/TSIG/HE secrets). The DB-backed
preconditions (schema, provider registry, TSIG algorithm) live in
:mod:`tests.test_startup_db`. Throwaway keys only; a failure message must name the
key *position*, never the raw material.
"""

from __future__ import annotations

import pytest

from astropath.crypto import Kek, generate_key
from astropath.startup import StartupError, validate_kek


def test_valid_kek_is_returned_usable() -> None:
    kek_raw = generate_key()

    kek = validate_kek(kek_raw)

    # The returned KEK round-trips against a fresh KEK built from the same key.
    assert kek.decrypt_str(Kek([kek_raw]).encrypt_str("ping")) == "ping"


def test_malformed_kek_fails_without_leaking_the_key() -> None:
    bad_kek = "this-is-not-a-fernet-key"

    with pytest.raises(StartupError) as excinfo:
        validate_kek(bad_kek)

    message = str(excinfo.value)
    assert "position 0" in message  # redacted to position...
    assert bad_kek not in message  # ...never the raw key material


def test_missing_kek_fails_fast() -> None:
    with pytest.raises(StartupError, match="credential KEK is not configured"):
        validate_kek("")


def test_none_kek_fails_fast() -> None:
    # An unset env yields None; it must fail identically to the empty string.
    with pytest.raises(StartupError, match="credential KEK is not configured"):
        validate_kek(None)
