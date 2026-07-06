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

"""Dispatcher unit tests (T-M1-08.., SPEC §3, §4, §5)."""

from __future__ import annotations

import dns.message
import dns.update

from astropath.data_plane.dispatcher import Action, classify_action


def _parsed_update(
    *, delete: bool = False, delete_rrset: bool = False
) -> dns.update.UpdateMessage:
    u = dns.update.UpdateMessage("example.com.")
    record = "_acme-challenge.example.com."
    if delete_rrset:
        u.delete(record, "TXT")
    elif delete:
        u.delete(record, "TXT", "tok")
    else:
        u.add(record, 300, "TXT", "tok")
    msg = dns.message.from_wire(u.to_wire())
    assert isinstance(msg, dns.update.UpdateMessage)
    return msg


def test_classify_add_is_present() -> None:
    rrset = _parsed_update().update[0]
    assert classify_action(rrset) is Action.PRESENT


def test_classify_delete_specific_rr_is_cleanup() -> None:
    """Class-NONE delete (cert-manager cleanup) routes to CLEANUP."""
    rrset = _parsed_update(delete=True).update[0]
    assert classify_action(rrset) is Action.CLEANUP


def test_classify_delete_entire_rrset_is_cleanup() -> None:
    """Class-ANY delete routes to CLEANUP."""
    rrset = _parsed_update(delete_rrset=True).update[0]
    assert classify_action(rrset) is Action.CLEANUP
