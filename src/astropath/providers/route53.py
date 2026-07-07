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

"""AWS Route 53 provider via aiobotocore (SPEC §5.8, HIGH-9).

Async-native ``aiobotocore``: each operation opens the client as an **async
context manager** (``[C7]`` pattern, SPEC §5.8) and awaits the coroutine API.
Endpoint resolution is the SDK's (region only) — no user-supplied URL (SSRF
closed, SPEC §5.5). Credentials are **explicit** (access key + secret from the
backend config), never ambient AWS env vars or instance-profile roles (SPEC
§5.8).

Semantics:

- ``present()`` — read-modify-write ``UPSERT``: read the current TXT rrset and
  write the **union** of existing + new values, so a second concurrent challenge
  (apex + wildcard SAN, or a 2nd Certificate) coexists rather than clobbering the
  first (SPEC §5.4). Re-presenting an existing value is a no-op success (§5.3).
- ``cleanup()`` — read the exact current rrset, drop only the specified value(s);
  ``DELETE`` the rrset with the **identical** body Route 53 requires for an exact
  match when nothing remains, else ``UPSERT`` the reduced set (SPEC §5.8). A
  name-only delete does not exist; cleaning an absent value is success (§5.3).
- ``validate()`` — a cheap authenticated ``GetHostedZone`` proving the
  credentials reach the configured zone (SPEC §5.8).

``supports_multivalue=True`` (SPEC §5.8): the rrset may hold several ``"token"``
values at once. TXT values are stored in Route 53 escaped-double-quote form.

Testability: the client is obtained from an injected :data:`Route53ClientFactory`
— a zero-arg callable returning the async client context manager. Production
builds the factory from :meth:`Route53Provider.from_config`; tests inject a fake
client at that seam (no network, no real AWS).

Secret discipline: the AWS secret access key lives in memory only, inside the
factory closure; it is never logged and never embedded in an error message
(errors carry only the botocore exception type / a non-secret identifier).
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from contextlib import AbstractAsyncContextManager
from typing import Any

from aiobotocore.config import AioConfig  # type: ignore[import-untyped]
from aiobotocore.session import get_session  # type: ignore[import-untyped]
from botocore.exceptions import (  # type: ignore[import-untyped]
    BotoCoreError,
    ClientError,
)
from pydantic import BaseModel, SecretStr

from astropath.providers.base import ConfigSchema, Provider, ProviderError, register

__all__ = ["Route53Config", "Route53Provider"]

# Route 53 is a global service; us-east-1 is its signing region when none is set.
_DEFAULT_REGION = "us-east-1"
# TTL for challenge TXT records (short — SPEC §5.8 example uses 60s).
_TXT_TTL = 60
# Explicit bounded timeouts / pool (never the implicit SDK defaults; SPEC §5.6).
_CONNECT_TIMEOUT = 5
_READ_TIMEOUT = 10
_MAX_POOL_CONNECTIONS = 20
# Optional INSYNC propagation poll (T-M5-04): interval + attempt bound.
_INSYNC_POLL_INTERVAL = 2.0
_INSYNC_MAX_ATTEMPTS = 30

# The aiobotocore route53 client is dynamically generated and has no precise
# public type; treat it as ``Any`` at the seam.
Route53Client = Any
#: A zero-arg factory yielding the async client context manager (the test seam).
Route53ClientFactory = Callable[[], AbstractAsyncContextManager[Route53Client]]


class Route53Config(BaseModel):
    """Route 53 backend shared config (SPEC §6.1, §5.8).

    Credentials are explicit and required; ``region`` is optional (Route 53 is
    global). No URL field exists — the SDK resolves the endpoint (SPEC §5.5).
    """

    access_key_id: str
    secret_access_key: SecretStr
    hosted_zone_id: str
    region: str | None = None
    # Opt-in: poll GetChange until INSYNC before signalling live (T-M5-04, §5.8).
    await_insync: bool = False


def _normalize_name(record_name: str) -> str:
    """Return the FQDN in Route 53 form: lower-case, single trailing dot."""
    return record_name.rstrip(".").lower() + "."


def _quote(token: str) -> str:
    """Wrap a raw TXT token in Route 53 escaped-double-quote form (SPEC §5.8).

    ACME DNS-01 tokens are quote-safe base64url, but backslash/quote are escaped
    regardless so the value is always a well-formed Route 53 character-string.
    """
    escaped = token.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


@register
class Route53Provider(Provider):
    """AWS Route 53 provider (SPEC §5.8).

    Multi-value contract (``supports_multivalue=True``, SPEC §5.4): one rrset may
    hold several challenge values at once. ``present`` unions a new value into the
    existing set (an apex + wildcard SAN, or a 2nd Certificate, coexist rather
    than clobber); ``cleanup`` removes only the named value(s) and deletes the
    rrset only once the last value is gone. Both are idempotent (SPEC §5.3).
    """

    type = "route53"
    supports_multivalue = True
    supports_delete = True

    def __init__(
        self,
        *,
        hosted_zone_id: str,
        client_factory: Route53ClientFactory,
        region: str | None = None,
        ttl: int = _TXT_TTL,
        await_insync: bool = False,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        insync_interval: float = _INSYNC_POLL_INTERVAL,
        insync_max_attempts: int = _INSYNC_MAX_ATTEMPTS,
    ) -> None:
        self._hosted_zone_id = hosted_zone_id
        self._client_factory = client_factory
        self._region = region
        self._ttl = ttl
        self._await_insync = await_insync
        self._sleep = sleep
        self._insync_interval = insync_interval
        self._insync_max_attempts = insync_max_attempts

    @property
    def hosted_zone_id(self) -> str:
        """The configured hosted-zone id (non-secret identifier)."""
        return self._hosted_zone_id

    @property
    def region(self) -> str | None:
        """The configured region, or ``None`` (defaults to us-east-1 at call)."""
        return self._region

    # -- registry / config ------------------------------------------------- #
    @classmethod
    def config_schema(cls) -> ConfigSchema:
        return Route53Config

    @classmethod
    def from_config(
        cls, config: Mapping[str, Any], *, http: Any = None
    ) -> Route53Provider:
        """Build from validated config (SPEC §5.8).

        ``http`` (Hurricane Electric's shared ``httpx`` client) is unused: Route 53
        owns its own ``aiobotocore`` session per the async-context-manager pattern
        (SPEC §5.8), so it accepts the parameter for ABC conformance and ignores
        it. Construction does no network I/O — the factory is a lazy closure.
        """
        cfg = Route53Config.model_validate(dict(config))
        return cls(
            hosted_zone_id=cfg.hosted_zone_id,
            client_factory=cls._default_client_factory(cfg),
            region=cfg.region,
            await_insync=cfg.await_insync,
        )

    @staticmethod
    def _default_client_factory(cfg: Route53Config) -> Route53ClientFactory:
        """Build the production factory closing over an aiobotocore session.

        The session (``get_session()``) is cheap and stateless; the actual client
        is created per operation inside ``async with`` (SPEC §5.8). The secret
        access key is captured in the closure and never surfaces elsewhere.
        """
        session = get_session()
        aio_config = AioConfig(
            connect_timeout=_CONNECT_TIMEOUT,
            read_timeout=_READ_TIMEOUT,
            max_pool_connections=_MAX_POOL_CONNECTIONS,
        )
        region = cfg.region or _DEFAULT_REGION
        access_key_id = cfg.access_key_id
        secret_access_key = cfg.secret_access_key.get_secret_value()

        def factory() -> Any:
            # aiobotocore is untyped; the return is the async client context
            # manager (typed Any at this seam) matching Route53ClientFactory.
            return session.create_client(
                "route53",
                region_name=region,
                aws_access_key_id=access_key_id,
                aws_secret_access_key=secret_access_key,
                config=aio_config,
            )

        return factory

    # -- provider operations ----------------------------------------------- #
    async def present(self, zone: str, record_name: str, values: list[str]) -> None:
        name = _normalize_name(record_name)
        new_values = [_quote(v) for v in values]
        async with self._client_factory() as client:
            existing = await self._read_rrset(client, name)
            current = _record_values(existing)
            merged = list(current)
            for value in new_values:
                if value not in merged:
                    merged.append(value)
            if merged == current:
                return  # every value already present — idempotent no-op (§5.3)
            await self._change(client, "UPSERT", name, self._ttl, merged)

    async def cleanup(self, zone: str, record_name: str, values: list[str]) -> None:
        name = _normalize_name(record_name)
        async with self._client_factory() as client:
            existing = await self._read_rrset(client, name)
            if existing is None:
                return  # already absent — idempotent (§5.3)
            current = _record_values(existing)
            if not values:
                remaining: list[str] = []  # class-ANY: delete the whole rrset
            else:
                remove = {_quote(v) for v in values}
                remaining = [v for v in current if v not in remove]
                if remaining == current:
                    return  # nothing matched — idempotent (§5.3)
            if remaining:
                await self._change(client, "UPSERT", name, self._ttl, remaining)
            else:
                # Exact-match DELETE: echo the identical body Route 53 requires
                # (same TTL and value set read back), SPEC §5.8.
                ttl = int(existing.get("TTL", self._ttl))
                await self._change(client, "DELETE", name, ttl, current)

    async def validate(self) -> None:
        try:
            async with self._client_factory() as client:
                await client.get_hosted_zone(Id=self._hosted_zone_id)
        except (ClientError, BotoCoreError) as exc:
            raise ProviderError(
                f"route53 GetHostedZone failed for zone "
                f"{self._hosted_zone_id!r}: {type(exc).__name__}"
            ) from exc

    # -- internals --------------------------------------------------------- #
    async def _read_rrset(
        self, client: Route53Client, name: str
    ) -> dict[str, Any] | None:
        """Return the exact TXT rrset for ``name`` (or ``None`` if absent).

        ``list_resource_record_sets`` returns records at-or-after
        ``StartRecordName`` in lexical order; request the single candidate and
        accept it only on an exact name + TXT-type match (SPEC §5.8).
        """
        try:
            resp = await client.list_resource_record_sets(
                HostedZoneId=self._hosted_zone_id,
                StartRecordName=name,
                StartRecordType="TXT",
                MaxItems="1",
            )
        except (ClientError, BotoCoreError) as exc:
            raise ProviderError(
                f"route53 ListResourceRecordSets failed: {type(exc).__name__}"
            ) from exc
        for rrset in resp.get("ResourceRecordSets", []):
            if rrset.get("Type") == "TXT" and _normalize_name(rrset["Name"]) == name:
                return dict(rrset)
        return None

    async def _change(
        self,
        client: Route53Client,
        action: str,
        name: str,
        ttl: int,
        values: list[str],
    ) -> None:
        """Submit one ChangeBatch (UPSERT or DELETE) for the TXT rrset."""
        batch = {
            "Changes": [
                {
                    "Action": action,
                    "ResourceRecordSet": {
                        "Name": name,
                        "Type": "TXT",
                        "TTL": ttl,
                        "ResourceRecords": [{"Value": value} for value in values],
                    },
                }
            ]
        }
        try:
            resp = await client.change_resource_record_sets(
                HostedZoneId=self._hosted_zone_id, ChangeBatch=batch
            )
        except (ClientError, BotoCoreError) as exc:
            raise ProviderError(
                f"route53 {action} failed for {name!r}: {type(exc).__name__}"
            ) from exc
        if self._await_insync:
            await self._wait_insync(client, resp["ChangeInfo"]["Id"])

    async def _wait_insync(self, client: Route53Client, change_id: str) -> None:
        """Poll GetChange until the change is INSYNC (opt-in; T-M5-04, SPEC §5.8).

        Reduces cert-manager self-check flakiness by only signalling the record
        live once Route 53 reports propagation to all its authoritative servers.
        Bounded by ``insync_max_attempts``; a timeout raises :class:`ProviderError`.
        """
        for _ in range(self._insync_max_attempts):
            try:
                resp = await client.get_change(Id=change_id)
            except (ClientError, BotoCoreError) as exc:
                raise ProviderError(
                    f"route53 GetChange failed: {type(exc).__name__}"
                ) from exc
            if resp["ChangeInfo"]["Status"] == "INSYNC":
                return
            await self._sleep(self._insync_interval)
        raise ProviderError(
            f"route53 change {change_id!r} not INSYNC after "
            f"{self._insync_max_attempts} polls"
        )


def _record_values(rrset: dict[str, Any] | None) -> list[str]:
    """Extract the (already Route 53-quoted) TXT values from a read rrset."""
    if rrset is None:
        return []
    return [str(record["Value"]) for record in rrset.get("ResourceRecords", [])]
