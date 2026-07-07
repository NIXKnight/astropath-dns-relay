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

"""Guard the shipped Route 53 IAM policy stays least-privilege (T-M5-03, §5.8).

Machine-verifies the scoped policy so an accidental broadening (a ``*`` resource,
a wildcard action, a dropped condition) fails CI rather than shipping.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

_POLICY_PATH = Path(__file__).resolve().parents[1] / "docs" / "route53-iam-policy.json"


@pytest.fixture(scope="module")
def policy() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(_POLICY_PATH.read_text(encoding="utf-8"))
    return data


def _statement(policy: dict[str, Any], sid: str) -> dict[str, Any]:
    for stmt in policy["Statement"]:
        if stmt.get("Sid") == sid:
            result: dict[str, Any] = stmt
            return result
    raise AssertionError(f"statement {sid!r} not found")


def _as_list(value: Any) -> list[str]:
    return value if isinstance(value, list) else [value]


def test_policy_version() -> None:
    assert json.loads(_POLICY_PATH.read_text())["Version"] == "2012-10-17"


def test_no_statement_grants_wildcard_resource_or_action(
    policy: dict[str, Any],
) -> None:
    for stmt in policy["Statement"]:
        for resource in _as_list(stmt["Resource"]):
            assert resource != "*", "hosted-zone ARN must never be *"
            assert resource.startswith("arn:aws:route53:::")
        for action in _as_list(stmt["Action"]):
            assert action != "*"
            assert not action.endswith(":*"), f"wildcard action {action!r} forbidden"
            assert action.startswith("route53:")


def test_write_statement_is_scoped_and_conditioned(policy: dict[str, Any]) -> None:
    write = _statement(policy, "AstropathAcmeChallengeWrite")
    assert write["Effect"] == "Allow"
    assert write["Action"] == "route53:ChangeResourceRecordSets"
    assert write["Resource"].startswith("arn:aws:route53:::hostedzone/")

    cond = write["Condition"]["ForAllValues:StringEquals"]
    names = cond["route53:ChangeResourceRecordSetsNormalizedRecordNames"]
    assert all(n.startswith("_acme-challenge.") for n in _as_list(names))
    assert _as_list(cond["route53:ChangeResourceRecordSetsRecordTypes"]) == ["TXT"]
    assert set(cond["route53:ChangeResourceRecordSetsActions"]) == {"UPSERT", "DELETE"}


def test_read_statements_present(policy: dict[str, Any]) -> None:
    read = _statement(policy, "AstropathReadRecordsAndZone")
    assert set(_as_list(read["Action"])) == {
        "route53:ListResourceRecordSets",
        "route53:GetHostedZone",
    }
    assert read["Resource"].startswith("arn:aws:route53:::hostedzone/")

    change = _statement(policy, "AstropathGetChange")
    assert change["Action"] == "route53:GetChange"
    assert change["Resource"] == "arn:aws:route53:::change/*"
