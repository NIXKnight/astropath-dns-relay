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

"""Registry pluggability + per-backend config wiring (T-M5-05, SPEC §5.2, §16.3).

Proves that adding Route 53 required only one provider file + one registry entry:
``build_data_plane`` constructs the provider from a decrypted ``BackendConfig``
(the per-backend credential wiring M2 deferred), keyed by ``Backend.type``, with
no data-plane changes needed to route to it. No Docker, no network, no real AWS —
the decrypt→construct path is exercised with a SecretCodec round-trip and an
httpx client Route 53 never touches.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import dns.name
import httpx
import pytest_asyncio

from astropath.bootstrap import (
    BackendConfig,
    BootstrapConfig,
    ZoneConfig,
    build_data_plane,
)
from astropath.crypto import Kek, generate_key
from astropath.providers.base import get_provider
from astropath.providers.hurricane import HurricaneProvider
from astropath.providers.route53 import Route53Config, Route53Provider
from astropath.store import SecretCodec

_R53_CONFIG = {
    "access_key_id": "AKIAFAKEWIRINGTEST00",
    "secret_access_key": "FAKESECRETfakesecretfakesecretwiring1234",
    "hosted_zone_id": "Z-WIRE-PROD",
    "region": "us-east-1",
}
_HE_KEY = "THROWAWAY-he-dynamic-key"


@pytest_asyncio.fixture
async def http_client() -> AsyncIterator[httpx.AsyncClient]:
    """A no-network httpx client (Route 53 ignores it; HE never calls it here)."""
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _req: httpx.Response(200, text="good"))
    )
    try:
        yield client
    finally:
        await client.aclose()


def _route53_zone(zone: str, backend: str) -> ZoneConfig:
    return ZoneConfig(
        zone=zone,
        provider="route53",
        record_name=f"_acme-challenge.{zone}",
        backend=backend,
    )


# --------------------------------------------------------------------------- #
# decrypt → construct: Route 53 built from a backend's config
# --------------------------------------------------------------------------- #
async def test_build_data_plane_constructs_route53_from_backend_config(
    http_client: httpx.AsyncClient,
) -> None:
    config = BootstrapConfig(
        backends=[
            BackendConfig(name="aws-prod", provider="route53", config=_R53_CONFIG)
        ],
        zones=[_route53_zone("example.com.", "aws-prod")],
    )
    runtime = build_data_plane(config, http_client=http_client)

    assert len(runtime.providers) == 1
    provider = runtime.providers[0]
    assert isinstance(provider, Route53Provider)
    assert provider.hosted_zone_id == "Z-WIRE-PROD"
    assert provider.region == "us-east-1"

    route = runtime.routing.match(dns.name.from_text("example.com."))
    assert route is not None
    assert route.provider is provider  # routed by Backend.type, no data-plane edit


async def test_hurricane_backend_keeps_empty_config_with_domain_key(
    http_client: httpx.AsyncClient,
) -> None:
    # Regression: HE rows carry empty backend config; the per-record dynamic key
    # still comes from the Domain scope (HIGH-7), even through the new wiring.
    config = BootstrapConfig(
        backends=[BackendConfig(name="he", provider="hurricane", config={})],
        zones=[
            ZoneConfig(
                zone="he.example.",
                provider="hurricane",
                record_name="_acme-challenge.he.example.",
                he_dynamic_key=_HE_KEY,
                backend="he",
            )
        ],
    )
    runtime = build_data_plane(config, http_client=http_client)
    provider = runtime.providers[0]
    assert isinstance(provider, HurricaneProvider)
    assert provider._key_for("_acme-challenge.he.example.") == _HE_KEY


async def test_mixed_backends_build_distinct_provider_instances(
    http_client: httpx.AsyncClient,
) -> None:
    config = BootstrapConfig(
        backends=[
            BackendConfig(name="he", provider="hurricane", config={}),
            BackendConfig(name="aws", provider="route53", config=_R53_CONFIG),
        ],
        zones=[
            ZoneConfig(
                zone="he.example.",
                provider="hurricane",
                record_name="_acme-challenge.he.example.",
                he_dynamic_key=_HE_KEY,
                backend="he",
            ),
            _route53_zone("aws.example.", "aws"),
        ],
    )
    runtime = build_data_plane(config, http_client=http_client)
    kinds = sorted(type(p).__name__ for p in runtime.providers)
    assert kinds == ["HurricaneProvider", "Route53Provider"]


async def test_two_route53_backends_are_separate_instances(
    http_client: httpx.AsyncClient,
) -> None:
    # Per-backend construction (not per-type): two Route 53 hosted zones with
    # distinct credentials must not share one instance.
    config = BootstrapConfig(
        backends=[
            BackendConfig(
                name="aws-a",
                provider="route53",
                config={**_R53_CONFIG, "hosted_zone_id": "Z-AAA"},
            ),
            BackendConfig(
                name="aws-b",
                provider="route53",
                config={**_R53_CONFIG, "hosted_zone_id": "Z-BBB"},
            ),
        ],
        zones=[
            _route53_zone("a.example.", "aws-a"),
            _route53_zone("b.example.", "aws-b"),
        ],
    )
    runtime = build_data_plane(config, http_client=http_client)
    assert len(runtime.providers) == 2

    zone_ids: dict[str, str] = {}
    for zone in ("a.example.", "b.example."):
        route = runtime.routing.match(dns.name.from_text(zone))
        assert route is not None
        assert isinstance(route.provider, Route53Provider)
        zone_ids[zone] = route.provider.hosted_zone_id
    assert zone_ids == {"a.example.": "Z-AAA", "b.example.": "Z-BBB"}


async def test_file_path_without_named_backends_groups_by_type(
    http_client: httpx.AsyncClient,
) -> None:
    # M1 file path (no BackendConfig, backend=None): providers grouped by type,
    # empty config — the wiring left the M1 path untouched.
    config = BootstrapConfig(
        zones=[
            ZoneConfig(
                zone="x.example.",
                provider="hurricane",
                record_name="_acme-challenge.x.example.",
                he_dynamic_key="K1",
            ),
            ZoneConfig(
                zone="y.example.",
                provider="hurricane",
                record_name="_acme-challenge.y.example.",
                he_dynamic_key="K2",
            ),
        ],
    )
    runtime = build_data_plane(config, http_client=http_client)
    assert len(runtime.providers) == 1  # one HE instance shared by both zones
    provider = runtime.providers[0]
    assert isinstance(provider, HurricaneProvider)
    assert provider._key_for("_acme-challenge.x.example.") == "K1"
    assert provider._key_for("_acme-challenge.y.example.") == "K2"


# --------------------------------------------------------------------------- #
# SPA auto-form + at-rest round-trip
# --------------------------------------------------------------------------- #
def test_config_schema_resolvable_via_registry() -> None:
    # A new provider gets a correct API + UI form purely from its registry entry
    # (SPEC §5.2 — the SPA reads config_schema()).
    assert get_provider("route53").config_schema() is Route53Config


def test_secret_codec_roundtrips_route53_backend_config() -> None:
    codec = SecretCodec(Kek([generate_key()]))
    token = codec.encrypt_json(_R53_CONFIG)
    # The exact at-rest path load_config_from_db uses: encrypt_json → decrypt_json.
    decrypted = codec.decrypt_json(token)
    assert decrypted == _R53_CONFIG
    provider = Route53Provider.from_config(decrypted)
    assert provider.hosted_zone_id == "Z-WIRE-PROD"
