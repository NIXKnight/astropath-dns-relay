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

"""Hurricane Electric provider unit tests (T-M1-18, SPEC §5.7).

Folds the T-TEST-06 acceptance content: HE response strings
(``good``/``nochg``/``badauth``/``nohost``), placeholder cleanup, single-value
rejection, and per-record-key handling. Uses ``httpx.MockTransport`` — no
network. The dynamic key is an obvious throwaway; the tests also assert it never
appears in an error message (secret discipline).
"""

from __future__ import annotations

from urllib.parse import parse_qs

import httpx
import pytest

from astropath.providers.base import ProviderError
from astropath.providers.hurricane import HurricaneProvider

_RECORD = "_acme-challenge.example.com."
_DYNKEY = "THROWAWAY-HE-DYNKEY-not-real"


def _provider(bodies: list[str], captured: list[httpx.Request]) -> HurricaneProvider:
    sequence = iter(bodies)

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        try:
            body = next(sequence)
        except StopIteration:
            body = bodies[-1]
        return httpx.Response(200, text=body)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return HurricaneProvider(client, {_RECORD: _DYNKEY})


def _form(request: httpx.Request) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(request.content.decode()).items()}


def test_class_flags() -> None:
    assert HurricaneProvider.type == "hurricane"
    assert HurricaneProvider.supports_multivalue is False
    assert HurricaneProvider.supports_delete is False


async def test_present_good_sends_expected_form() -> None:
    captured: list[httpx.Request] = []
    provider = _provider(["good"], captured)
    await provider.present("example.com.", _RECORD, ["token-value-123"])

    assert len(captured) == 1
    form = _form(captured[0])
    assert form["hostname"] == "_acme-challenge.example.com"  # no trailing dot
    assert form["txt"] == "token-value-123"
    assert form["password"] == _DYNKEY
    assert str(captured[0].url) == HurricaneProvider.ENDPOINT


async def test_present_nochg_is_success() -> None:
    provider = _provider(["nochg"], [])
    await provider.present("example.com.", _RECORD, ["tok"])  # no raise


@pytest.mark.parametrize("body", ["badauth", "nohost"])
async def test_hard_error_responses_raise(body: str) -> None:
    provider = _provider([body], [])
    with pytest.raises(ProviderError) as exc:
        await provider.present("example.com.", _RECORD, ["tok"])
    assert body in str(exc.value)
    assert _DYNKEY not in str(exc.value)  # credential never leaks into the error


async def test_unexpected_response_raises() -> None:
    provider = _provider(["wat"], [])
    with pytest.raises(ProviderError):
        await provider.present("example.com.", _RECORD, ["tok"])


async def test_cleanup_overwrites_with_placeholder() -> None:
    captured: list[httpx.Request] = []
    provider = _provider(["good"], captured)
    await provider.cleanup("example.com.", _RECORD, ["tok"])
    # cleanup writes the sentinel placeholder, not a delete.
    assert _form(captured[0])["txt"] == "acme-challenge-cleared"


async def test_multi_value_rejected_before_request() -> None:
    captured: list[httpx.Request] = []
    provider = _provider(["good"], captured)
    with pytest.raises(ProviderError, match="exactly one"):
        await provider.present("example.com.", _RECORD, ["a", "b"])
    assert captured == []  # rejected before any HTTP call


async def test_missing_record_key_raises_before_request() -> None:
    captured: list[httpx.Request] = []
    provider = _provider(["good"], captured)
    with pytest.raises(ProviderError, match="no HE dynamic key"):
        await provider.present("other.com.", "_acme-challenge.other.com.", ["tok"])
    assert captured == []


async def test_validate_requires_record_keys() -> None:
    provider = _provider(["good"], [])
    await provider.validate()  # has a key -> ok

    empty = HurricaneProvider(
        httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, text="good")
            )
        )
    )
    with pytest.raises(ProviderError):
        await empty.validate()


# --------------------------------------------------------------------------- #
# T-TEST-06 gap-fill: the four named strings, default-placeholder cleanup, and
# single-value reject are proven above. The cases below close the remaining
# facets of the same AC clauses — the full HE hard-error set, realistic wire
# parsing, and the *configurable* placeholder path (constructor + from_config).
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("body", ["!yours", "notfqdn", "abuse"])
async def test_additional_he_error_strings_map_to_hard_error(body: str) -> None:
    """AC 'error strings mapped': HE hard-error tokens beyond badauth/nohost are
    mapped to a rejection (not the 'unexpected response' branch) and never leak
    the per-record key."""
    provider = _provider([body], [])
    with pytest.raises(ProviderError) as exc:
        await provider.present("example.com.", _RECORD, ["tok"])
    message = str(exc.value)
    assert body in message
    assert "rejected" in message  # hard-error branch, not "unexpected response"
    assert _DYNKEY not in message


@pytest.mark.parametrize(
    "body", ["good\n", "good 203.0.113.5", "nochg\n", "GOOD", "NoChg"]
)
async def test_success_strings_parsed_from_realistic_responses(body: str) -> None:
    """AC 'success strings mapped': HE returns the status token with trailing
    data / newline / arbitrary case; the first token maps case-insensitively to
    success (no raise), matching real HE wire output."""
    provider = _provider([body], [])
    await provider.present("example.com.", _RECORD, ["tok"])  # no raise


async def test_cleanup_uses_configured_placeholder() -> None:
    """AC 'supports_delete=False placeholder path': the sentinel is configurable
    and cleanup issues a *full* authenticated HE update (hostname + password +
    the configured placeholder), not a delete."""
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, text="good")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = HurricaneProvider(
        client, {_RECORD: _DYNKEY}, cleanup_placeholder="my-sentinel"
    )
    await provider.cleanup("example.com.", _RECORD, ["ignored"])

    form = _form(captured[0])
    assert form["txt"] == "my-sentinel"  # configured sentinel, not the default
    assert form["hostname"] == "_acme-challenge.example.com"
    assert form["password"] == _DYNKEY  # cleanup overwrite is a full HE update


async def test_from_config_wires_cleanup_placeholder() -> None:
    """AC 'placeholder path': config_schema/from_config drive the cleanup
    sentinel end-to-end (config dict -> HurricaneConfig -> cleanup write)."""
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, text="good")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = HurricaneProvider.from_config(
        {"cleanup_placeholder": "cfg-sentinel"}, http=client
    )
    provider.register_record_key(_RECORD, _DYNKEY)
    await provider.cleanup("example.com.", _RECORD, ["ignored"])

    assert _form(captured[0])["txt"] == "cfg-sentinel"


async def test_non_200_http_status_maps_to_provider_error() -> None:
    """AC 'error mapped': a non-200 HTTP status (transport-level, before any HE
    body token) surfaces as a ProviderError naming the status, no key leak. A
    non-retryable 403 is used so no app-level backoff wait is incurred."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="err")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = HurricaneProvider(client, {_RECORD: _DYNKEY})
    with pytest.raises(ProviderError) as exc:
        await provider.present("example.com.", _RECORD, ["tok"])
    assert "403" in str(exc.value)
    assert _DYNKEY not in str(exc.value)


async def test_transport_error_maps_to_provider_error_without_leaking() -> None:
    """AC 'error mapped': an httpx transport failure becomes a ProviderError
    whose message carries only the exception *type* — never the endpoint URL or
    the per-record credential."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    provider = HurricaneProvider(client, {_RECORD: _DYNKEY})
    with pytest.raises(ProviderError) as exc:
        await provider.present("example.com.", _RECORD, ["tok"])
    message = str(exc.value)
    assert "ConnectError" in message
    assert _DYNKEY not in message
    assert "dyn.dns.he.net" not in message  # endpoint not echoed either
