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

"""Challenge dispatcher: zone → backend → provider (SPEC §3, §4, §5).

Resolves the target zone from the UPDATE ZONE section, enforces the
``_acme-challenge`` TXT write-surface allowlist (BLOCKER-2), validates and
normalizes the TXT value, serializes pushes per FQDN (HE single-value), and
calls ``provider.present`` / ``provider.cleanup``. A provider failure maps to
SERVFAIL; success maps to NOERROR (SPEC §3.6).
"""

from __future__ import annotations

from enum import Enum

import dns.rdataclass
import dns.rrset


class Action(Enum):
    """Whether an update-section rrset publishes or clears a challenge value."""

    PRESENT = "present"
    CLEANUP = "cleanup"


def classify_action(rrset: dns.rrset.RRset) -> Action:
    """Classify an UPDATE-section rrset as present vs cleanup (SPEC §3.8).

    dnspython records the RFC2136 update class on ``rrset.deleting`` (proven in
    :mod:`tests.test_dnspython_asserts`): ``None`` for an add (class IN),
    ``NONE`` (254, delete a specific RR) or ``ANY`` (255, delete the rrset) for a
    cleanup. Branching on ``rdclass`` is wrong — it stays IN for the rdata.
    """
    if rrset.deleting is None:
        return Action.PRESENT
    if rrset.deleting in (dns.rdataclass.NONE, dns.rdataclass.ANY):
        return Action.CLEANUP
    raise ValueError(f"unexpected update class deleting={rrset.deleting!r}")
