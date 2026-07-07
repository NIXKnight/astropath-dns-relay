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

"""Algorithm-bound TSIG keyring tests (T-M1-01, SPEC §3.1, BLOCKER-1).

Proves keyring values are ``dns.tsig.Key`` objects (not raw bytes) and that the
bound algorithm is enforced: a client signing under a different HMAC algorithm
than the server-bound key is rejected — the inbound wire algorithm cannot
override the server's choice. Throwaway secrets only.
"""

from __future__ import annotations

import base64

import dns.message
import dns.name
import dns.tsig
import dns.update
import pytest

from astropath.data_plane.tsig import (
    DEFAULT_ALGORITHM,
    TsigKeySpec,
    UnknownAlgorithm,
    algorithm_from_text,
    build_keyring,
)

_SECRET_B64 = base64.b64encode(b"0123456789abcdef0123456789abcdef").decode()


def test_build_keyring_values_are_key_objects() -> None:
    keyring = build_keyring([TsigKeySpec("cm-key.", DEFAULT_ALGORITHM, _SECRET_B64)])
    ((name, key),) = keyring.items()
    assert isinstance(key, dns.tsig.Key)  # NOT raw bytes
    assert name == dns.name.from_text("cm-key.")
    assert key.algorithm == dns.tsig.HMAC_SHA256


@pytest.mark.parametrize(
    "text",
    ["hmac-sha256", "HMAC-SHA256", "hmac-sha256.", "HMACSHA256", " hmac-sha256 "],
)
def test_algorithm_from_text_accepts_dashed_and_dashless(text: str) -> None:
    assert algorithm_from_text(text) == dns.tsig.HMAC_SHA256


def test_algorithm_from_text_rejects_unknown() -> None:
    with pytest.raises(UnknownAlgorithm):
        algorithm_from_text("hmac-sha999")


def test_bound_algorithm_cannot_be_overridden_by_wire() -> None:
    """Security property (SPEC §3.1): the server-bound algorithm wins.

    The keyring binds ``hmac-sha256``. A client that signs the same key name
    with ``hmac-sha512`` is rejected at verification (dnspython raises
    ``BadAlgorithm``); the message is never accepted, so the attacker cannot
    downgrade/substitute the HMAC algorithm.
    """
    keyname = dns.name.from_text("cm-key.")
    server_keyring = build_keyring([TsigKeySpec("cm-key.", "hmac-sha256", _SECRET_B64)])

    # Client signs with a DIFFERENT algorithm under the same key name.
    client = dns.update.UpdateMessage(
        "example.com.",
        keyname=keyname,
        keyring={keyname: dns.tsig.Key("cm-key.", _SECRET_B64, dns.tsig.HMAC_SHA512)},
        keyalgorithm=dns.tsig.HMAC_SHA512,
    )
    client.add("_acme-challenge.example.com.", 300, "TXT", "tok")
    wire = client.to_wire()

    with pytest.raises(dns.tsig.BadAlgorithm):
        dns.message.from_wire(wire, keyring=server_keyring)


def test_matching_algorithm_verifies() -> None:
    keyname = dns.name.from_text("cm-key.")
    server_keyring = build_keyring([TsigKeySpec("cm-key.", "hmac-sha256", _SECRET_B64)])
    client = dns.update.UpdateMessage(
        "example.com.",
        keyname=keyname,
        keyring=server_keyring,
        keyalgorithm=dns.tsig.HMAC_SHA256,
    )
    client.add("_acme-challenge.example.com.", 300, "TXT", "tok")
    msg = dns.message.from_wire(client.to_wire(), keyring=server_keyring)
    assert msg.had_tsig is True
