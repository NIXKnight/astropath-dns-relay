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

"""Route 53 provider unit tests (T-M5-01, folds T-TEST-13; SPEC §5.8).

A fake aiobotocore client is injected at the ``client_factory`` seam — no
network, no real AWS. Covers UPSERT present, read-then-exact-match DELETE
cleanup, escaped-double-quote TXT values, ChangeBatch field names against the
pinned botocore model ([ASSERT], T-TEST-13), ``validate()`` success/failure,
error → ``ProviderError`` (without leaking the underlying botocore message), and
config-schema rejection. The AWS credentials are obvious throwaways.
"""

from __future__ import annotations

from collections.abc import Sequence
from contextlib import asynccontextmanager
from typing import Any

import pytest
from botocore.exceptions import ClientError  # type: ignore[import-untyped]
from pydantic import ValidationError

from astropath.providers.base import ProviderError
from astropath.providers.route53 import (
    Route53ClientFactory,
    Route53Config,
    Route53Provider,
)

_ZONE = "example.com."
_RECORD = "_acme-challenge.example.com."
_HOSTED_ZONE_ID = "Z-FAKE-HOSTEDZONE"
_ACCESS_KEY = "AKIAFAKEFAKEFAKEFAKE"
_SECRET_KEY = "FAKESECRETfakesecretfakesecretfakesecret"
# A marker embedded in the fake botocore error to prove it never leaks upward.
_SENSITIVE_MARKER = "SENSITIVE-BOTO-DETAIL-should-not-leak"


def _client_error(code: str = "AccessDenied") -> ClientError:
    return ClientError(
        {"Error": {"Code": code, "Message": _SENSITIVE_MARKER}}, "Route53Op"
    )


class _FakeRoute53Client:
    """Records calls and returns canned responses (no network, no AWS)."""

    def __init__(
        self,
        *,
        rrsets: list[dict[str, Any]] | None = None,
        errors: set[str] | None = None,
        change_statuses: Sequence[str] = ("INSYNC",),
    ) -> None:
        self._rrsets = rrsets if rrsets is not None else []
        self._errors = errors or set()
        self._change_statuses = list(change_statuses)
        self.list_calls: list[dict[str, Any]] = []
        self.change_batches: list[dict[str, Any]] = []
        self.get_change_calls: list[dict[str, Any]] = []
        self.get_hosted_zone_calls: list[dict[str, Any]] = []

    async def list_resource_record_sets(self, **kwargs: Any) -> dict[str, Any]:
        self.list_calls.append(kwargs)
        if "list" in self._errors:
            raise _client_error()
        return {"ResourceRecordSets": [dict(r) for r in self._rrsets]}

    async def change_resource_record_sets(self, **kwargs: Any) -> dict[str, Any]:
        batch = kwargs["ChangeBatch"]
        self.change_batches.append(batch)
        if "change" in self._errors:
            raise _client_error()
        # Apply to internal state so a later read reflects the write (realistic
        # for read-modify-write / multi-op lifecycle tests).
        for change in batch["Changes"]:
            self._apply(change)
        return {"ChangeInfo": {"Id": "/change/C-FAKE", "Status": "PENDING"}}

    def _apply(self, change: dict[str, Any]) -> None:
        rrset = change["ResourceRecordSet"]
        name, rtype = rrset["Name"], rrset["Type"]
        self._rrsets = [
            r for r in self._rrsets if not (r["Name"] == name and r["Type"] == rtype)
        ]
        if change["Action"] == "UPSERT":
            self._rrsets.append(dict(rrset))

    async def get_change(self, **kwargs: Any) -> dict[str, Any]:
        self.get_change_calls.append(kwargs)
        if "getchange" in self._errors:
            raise _client_error()
        idx = min(len(self.get_change_calls) - 1, len(self._change_statuses) - 1)
        return {
            "ChangeInfo": {"Id": kwargs["Id"], "Status": self._change_statuses[idx]}
        }

    async def get_hosted_zone(self, **kwargs: Any) -> dict[str, Any]:
        self.get_hosted_zone_calls.append(kwargs)
        if "gethostedzone" in self._errors:
            raise _client_error()
        return {"HostedZone": {"Id": kwargs["Id"], "Name": _ZONE}}


def _factory(client: _FakeRoute53Client) -> Route53ClientFactory:
    """A zero-arg factory yielding ``client`` as an async context manager."""

    @asynccontextmanager
    async def _cm() -> Any:
        yield client

    return _cm


def _provider(client: _FakeRoute53Client, **kwargs: Any) -> Route53Provider:
    kwargs.setdefault("hosted_zone_id", _HOSTED_ZONE_ID)
    kwargs.setdefault("region", "us-east-1")
    return Route53Provider(client_factory=_factory(client), **kwargs)


def _txt_rrset(*values: str, ttl: int = 60) -> dict[str, Any]:
    return {
        "Name": _RECORD,
        "Type": "TXT",
        "TTL": ttl,
        "ResourceRecords": [{"Value": v} for v in values],
    }


def _only_change(client: _FakeRoute53Client) -> dict[str, Any]:
    assert len(client.change_batches) == 1
    changes = client.change_batches[0]["Changes"]
    assert len(changes) == 1
    change: dict[str, Any] = changes[0]
    return change


# --------------------------------------------------------------------------- #
# Class contract / config schema
# --------------------------------------------------------------------------- #
def test_class_flags() -> None:
    assert Route53Provider.type == "route53"
    assert Route53Provider.supports_multivalue is True
    assert Route53Provider.supports_delete is True


def test_config_schema_is_route53_config() -> None:
    assert Route53Provider.config_schema() is Route53Config


def test_from_config_builds_without_network() -> None:
    provider = Route53Provider.from_config(
        {
            "access_key_id": _ACCESS_KEY,
            "secret_access_key": _SECRET_KEY,
            "hosted_zone_id": _HOSTED_ZONE_ID,
            "region": "eu-west-1",
        },
        http=object(),  # HE's httpx client — ignored by Route 53
    )
    assert isinstance(provider, Route53Provider)
    assert provider.hosted_zone_id == _HOSTED_ZONE_ID
    assert provider.region == "eu-west-1"


def test_config_rejects_missing_required_fields() -> None:
    with pytest.raises(ValidationError):
        Route53Config.model_validate({"region": "us-east-1"})


def test_config_secret_access_key_is_redacted_in_repr() -> None:
    cfg = Route53Config.model_validate(
        {
            "access_key_id": _ACCESS_KEY,
            "secret_access_key": _SECRET_KEY,
            "hosted_zone_id": _HOSTED_ZONE_ID,
        }
    )
    assert _SECRET_KEY not in repr(cfg)  # SecretStr never renders its value
    assert cfg.secret_access_key.get_secret_value() == _SECRET_KEY


# --------------------------------------------------------------------------- #
# present() — UPSERT with escaped-double-quote values
# --------------------------------------------------------------------------- #
async def test_present_on_empty_upserts_quoted_value() -> None:
    client = _FakeRoute53Client(rrsets=[])
    provider = _provider(client)

    await provider.present(_ZONE, _RECORD, ["tok-abc-123"])

    change = _only_change(client)
    assert change["Action"] == "UPSERT"
    rrset = change["ResourceRecordSet"]
    assert rrset["Name"] == _RECORD
    assert rrset["Type"] == "TXT"
    assert rrset["TTL"] == 60
    # TXT value stored escaped-double-quoted (SPEC §5.8).
    assert rrset["ResourceRecords"] == [{"Value": '"tok-abc-123"'}]


async def test_present_reads_before_writing() -> None:
    client = _FakeRoute53Client(rrsets=[])
    provider = _provider(client)
    await provider.present(_ZONE, _RECORD, ["tok"])
    # Read-modify-write: the record set is read before the change is submitted.
    assert len(client.list_calls) == 1
    assert client.list_calls[0]["StartRecordType"] == "TXT"
    assert len(client.change_batches) == 1


async def test_present_escapes_quote_and_backslash() -> None:
    client = _FakeRoute53Client(rrsets=[])
    provider = _provider(client)
    await provider.present(_ZONE, _RECORD, ['weird"\\value'])
    rrset = _only_change(client)["ResourceRecordSet"]
    assert rrset["ResourceRecords"] == [{"Value": '"weird\\"\\\\value"'}]


async def test_present_existing_value_is_idempotent_noop() -> None:
    client = _FakeRoute53Client(rrsets=[_txt_rrset('"tok"')])
    provider = _provider(client)
    await provider.present(_ZONE, _RECORD, ["tok"])
    # Value already present → no change submitted (idempotent, SPEC §5.3).
    assert client.change_batches == []


# --------------------------------------------------------------------------- #
# cleanup() — read then exact-match DELETE
# --------------------------------------------------------------------------- #
async def test_cleanup_reads_then_deletes_exact_body() -> None:
    existing = _txt_rrset('"tok-abc-123"', ttl=45)
    client = _FakeRoute53Client(rrsets=[existing])
    provider = _provider(client)

    await provider.cleanup(_ZONE, _RECORD, ["tok-abc-123"])

    assert len(client.list_calls) == 1  # read-before-delete (SPEC §5.8)
    change = _only_change(client)
    assert change["Action"] == "DELETE"
    # DELETE echoes the identical body Route 53 requires (TTL + value set).
    rrset = change["ResourceRecordSet"]
    assert rrset["TTL"] == 45
    assert rrset["ResourceRecords"] == [{"Value": '"tok-abc-123"'}]


async def test_cleanup_absent_record_is_noop() -> None:
    client = _FakeRoute53Client(rrsets=[])
    provider = _provider(client)
    await provider.cleanup(_ZONE, _RECORD, ["tok"])
    assert client.change_batches == []  # nothing to delete — idempotent


async def test_cleanup_absent_value_is_noop() -> None:
    client = _FakeRoute53Client(rrsets=[_txt_rrset('"other"')])
    provider = _provider(client)
    await provider.cleanup(_ZONE, _RECORD, ["tok"])  # value not present
    assert client.change_batches == []  # idempotent — no write


# --------------------------------------------------------------------------- #
# validate() — GetHostedZone probe
# --------------------------------------------------------------------------- #
async def test_validate_success() -> None:
    client = _FakeRoute53Client()
    provider = _provider(client)
    await provider.validate()  # no raise
    assert client.get_hosted_zone_calls[0]["Id"] == _HOSTED_ZONE_ID


async def test_validate_failure_raises_provider_error() -> None:
    client = _FakeRoute53Client(errors={"gethostedzone"})
    provider = _provider(client)
    with pytest.raises(ProviderError):
        await provider.validate()


# --------------------------------------------------------------------------- #
# Error mapping + secret discipline
# --------------------------------------------------------------------------- #
async def test_present_change_error_maps_to_provider_error() -> None:
    client = _FakeRoute53Client(rrsets=[], errors={"change"})
    provider = _provider(client)
    with pytest.raises(ProviderError) as exc:
        await provider.present(_ZONE, _RECORD, ["tok"])
    # The underlying botocore message never propagates upward (secret discipline).
    assert _SENSITIVE_MARKER not in str(exc.value)
    assert "UPSERT" in str(exc.value)


async def test_list_error_maps_to_provider_error() -> None:
    client = _FakeRoute53Client(errors={"list"})
    provider = _provider(client)
    with pytest.raises(ProviderError) as exc:
        await provider.present(_ZONE, _RECORD, ["tok"])
    assert _SENSITIVE_MARKER not in str(exc.value)


# --------------------------------------------------------------------------- #
# T-M5-02 — multi-value TXT coexistence (SPEC §5.4, §5.8)
# --------------------------------------------------------------------------- #
def _last_change(client: _FakeRoute53Client) -> dict[str, Any]:
    change: dict[str, Any] = client.change_batches[-1]["Changes"][0]
    return change


def _values_of(change: dict[str, Any]) -> list[str]:
    return [rr["Value"] for rr in change["ResourceRecordSet"]["ResourceRecords"]]


async def test_present_two_values_at_once() -> None:
    client = _FakeRoute53Client(rrsets=[])
    provider = _provider(client)
    await provider.present(_ZONE, _RECORD, ["tok1", "tok2"])
    change = _only_change(client)
    assert change["Action"] == "UPSERT"
    assert _values_of(change) == ['"tok1"', '"tok2"']


async def test_present_adds_value_without_clobbering_existing() -> None:
    # apex + wildcard SAN: a second challenge on the same name must coexist.
    client = _FakeRoute53Client(rrsets=[_txt_rrset('"tok1"')])
    provider = _provider(client)
    await provider.present(_ZONE, _RECORD, ["tok2"])
    change = _only_change(client)
    assert change["Action"] == "UPSERT"
    assert _values_of(change) == ['"tok1"', '"tok2"']  # both held concurrently


async def test_cleanup_one_of_two_keeps_the_other() -> None:
    client = _FakeRoute53Client(rrsets=[_txt_rrset('"tok1"', '"tok2"')])
    provider = _provider(client)
    await provider.cleanup(_ZONE, _RECORD, ["tok1"])
    change = _only_change(client)
    # Reduced set is UPSERTed (not a whole-rrset delete) — tok2 survives.
    assert change["Action"] == "UPSERT"
    assert _values_of(change) == ['"tok2"']


async def test_cleanup_removing_all_values_deletes_rrset() -> None:
    client = _FakeRoute53Client(rrsets=[_txt_rrset('"tok1"', '"tok2"')])
    provider = _provider(client)
    await provider.cleanup(_ZONE, _RECORD, ["tok1", "tok2"])
    change = _only_change(client)
    assert change["Action"] == "DELETE"
    assert _values_of(change) == ['"tok1"', '"tok2"']  # exact body echoed


async def test_multivalue_lifecycle_coexist_then_delete() -> None:
    # Full sequence against a stateful fake: two independent challenges land,
    # coexist, then each is cleaned up in turn — the rrset is deleted only when
    # the last value is removed (SPEC §5.4).
    client = _FakeRoute53Client(rrsets=[])
    provider = _provider(client)

    await provider.present(_ZONE, _RECORD, ["tok1"])
    assert _values_of(_last_change(client)) == ['"tok1"']

    await provider.present(_ZONE, _RECORD, ["tok2"])
    assert _last_change(client)["Action"] == "UPSERT"
    assert _values_of(_last_change(client)) == ['"tok1"', '"tok2"']

    await provider.cleanup(_ZONE, _RECORD, ["tok1"])
    assert _last_change(client)["Action"] == "UPSERT"
    assert _values_of(_last_change(client)) == ['"tok2"']

    await provider.cleanup(_ZONE, _RECORD, ["tok2"])
    assert _last_change(client)["Action"] == "DELETE"
    assert _values_of(_last_change(client)) == ['"tok2"']
