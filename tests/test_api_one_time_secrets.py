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

"""One-time-secret revoke/recreate flow (T-M3-15, SPEC §16, LOW-1).

The invariant: a generated secret (TSIG key, API token, HE per-record key, backend
config) is returned **exactly once** at creation and *no read endpoint ever
re-returns it*; recovery of a lost secret is revoke + recreate, never redisplay.

Two complementary proofs:

* **Structural** — walk the generated OpenAPI and assert that no ``GET`` response
  schema exposes a secret-bearing property. This is self-maintaining: any future
  route that leaks a secret on read fails here without a bespoke test.
* **Behavioural** — against real Postgres (Docker-gated), create a TSIG key and an
  API token, then confirm the secret never reappears on list and that the recovery
  path (delete + recreate) yields a *new* value, never the old one.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from typing import Any

import httpx
import pytest_asyncio
from tests._api import api_client, seed_api_token
from tests.test_api_app import make_settings

from astropath.api.app import create_app
from astropath.api.schemas import ONE_TIME_SECRET_NOTICE
from astropath.crypto import Kek, generate_key
from astropath.db import Database

_KEK = Kek([generate_key()])

# Property names that carry (or could reconstruct) a secret. None may appear in any
# GET response schema. ``has_secret`` is deliberately excluded — it is a boolean
# presence flag, not the value.
_SECRET_PROPERTIES = frozenset(
    {"secret", "token", "token_hash", "he_dynamic_key", "secret_encrypted", "config"}
)


def _resolve(schema: dict[str, Any], components: dict[str, Any]) -> dict[str, Any]:
    ref = schema.get("$ref")
    if ref is None:
        return schema
    name = ref.rsplit("/", 1)[-1]
    resolved: dict[str, Any] = components.get(name, {})
    return resolved


def _property_names(
    schema: dict[str, Any], components: dict[str, Any], seen: set[str]
) -> Iterator[str]:
    """Yield every property name reachable from ``schema`` (refs/arrays/unions)."""
    ref = schema.get("$ref")
    if ref is not None:
        if ref in seen:
            return
        seen.add(ref)
        yield from _property_names(_resolve(schema, components), components, seen)
        return
    for prop_name, prop_schema in (schema.get("properties") or {}).items():
        yield prop_name
        yield from _property_names(prop_schema, components, seen)
    if "items" in schema:
        yield from _property_names(schema["items"], components, seen)
    for keyword in ("anyOf", "oneOf", "allOf"):
        for member in schema.get(keyword, ()):
            yield from _property_names(member, components, seen)


def _response_schema(operation: dict[str, Any]) -> dict[str, Any]:
    for status_code, response in operation.get("responses", {}).items():
        if not str(status_code).startswith("2"):
            continue
        content = response.get("content", {}).get("application/json")
        if content and "schema" in content:
            return content["schema"]  # type: ignore[no-any-return]
    return {}


@pytest_asyncio.fixture
async def client(api_db: Database) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(settings=make_settings(), database=api_db, kek=_KEK)
    headers = await seed_api_token(api_db)
    async with api_client(app) as c:
        c.headers.update(headers)
        yield c


def test_no_get_response_schema_exposes_a_secret() -> None:
    """No read endpoint may re-return a generated secret (the T-M3-15 AC)."""
    app = create_app(settings=make_settings())
    spec = app.openapi()
    components = spec.get("components", {}).get("schemas", {})

    offenders: list[str] = []
    for path, operations in spec["paths"].items():
        get = operations.get("get")
        if get is None:
            continue
        leaked = {
            name
            for name in _property_names(_response_schema(get), components, set())
            if name in _SECRET_PROPERTIES
        }
        if leaked:
            offenders.append(f"GET {path}: {sorted(leaked)}")
    assert not offenders, f"read endpoints leak secrets: {offenders}"


def test_create_endpoints_are_the_only_place_a_secret_appears() -> None:
    """Positive control: the secret exists only on the one-time create responses."""
    app = create_app(settings=make_settings())
    spec = app.openapi()
    components = spec.get("components", {}).get("schemas", {})

    tsig_post = spec["paths"]["/api/v1/tsig-keys"]["post"]
    token_post = spec["paths"]["/api/v1/tokens"]["post"]
    tsig_props = set(_property_names(_response_schema(tsig_post), components, set()))
    token_props = set(_property_names(_response_schema(token_post), components, set()))
    assert "secret" in tsig_props
    assert "token" in token_props


def test_openapi_carries_the_revoke_recreate_copy() -> None:
    """The 'copy state' (revoke + recreate, never redisplay) is machine-readable."""
    app = create_app(settings=make_settings())
    spec = app.openapi()
    for path in ("/api/v1/tsig-keys", "/api/v1/tokens"):
        responses = spec["paths"][path]["post"]["responses"]
        described = " ".join(r.get("description", "") for r in responses.values())
        assert ONE_TIME_SECRET_NOTICE in described
    assert "never redisplayed" in ONE_TIME_SECRET_NOTICE


async def test_tsig_secret_recovery_is_revoke_then_recreate(
    client: httpx.AsyncClient,
) -> None:
    first = await client.post("/api/v1/tsig-keys", json={"name": "rekey."})
    original_secret = first.json()["secret"]
    key_id = first.json()["id"]

    # No read path returns the secret again — recovery cannot be "look it up".
    listing = await client.get("/api/v1/tsig-keys")
    assert original_secret not in listing.text

    # Recovery = revoke + recreate. The new secret is a fresh value.
    assert (await client.delete(f"/api/v1/tsig-keys/{key_id}")).status_code == 204
    second = await client.post("/api/v1/tsig-keys", json={"name": "rekey."})
    assert second.status_code == 201
    assert second.json()["secret"] != original_secret


async def test_api_token_recovery_is_revoke_then_recreate(
    client: httpx.AsyncClient,
) -> None:
    first = await client.post("/api/v1/tokens", json={"name": "rotate"})
    original_token = first.json()["token"]
    token_id = first.json()["id"]

    listing = await client.get("/api/v1/tokens")
    assert original_token not in listing.text

    assert (await client.delete(f"/api/v1/tokens/{token_id}")).status_code == 204
    second = await client.post("/api/v1/tokens", json={"name": "rotate"})
    assert second.status_code == 201
    assert second.json()["token"] != original_token
