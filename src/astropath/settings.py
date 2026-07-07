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

"""Application configuration via pydantic-settings v2 (SPEC §10).

``Settings`` reads process environment variables prefixed ``ASTROPATH_``
(SPEC §1.4, §10.1). Bootstrap secrets are typed :class:`~pydantic.SecretStr` so
their values never appear in ``repr()``, ``str()``, logs, tracebacks, or
``model_dump()`` / ``model_dump_json()`` output; the real value is available
only via ``.get_secret_value()`` at the point of use (SPEC secret discipline).
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

__all__ = ["Settings", "get_settings"]


class Settings(BaseSettings):
    """Typed application settings sourced from the ``ASTROPATH_`` environment.

    Only bootstrap secrets live in the environment (SPEC §10.2): the database
    DSN, the credential KEK/keylist, the admin password hash, and the session
    signing secret. TSIG keys and API tokens are deliberately *not* environment
    variables — they are generated in the panel and stored encrypted/hashed
    (M2+) or in the M1 bootstrap file.
    """

    model_config = SettingsConfigDict(
        env_prefix="ASTROPATH_",
        env_nested_delimiter="__",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Bootstrap secrets (SecretStr — never logged; redact to <REDACTED>) ---
    database_dsn: SecretStr
    """``postgresql+asyncpg://…`` DSN (async driver scheme, never plain ``postgresql://``)."""

    credential_kek: SecretStr
    """Ordered Fernet keylist (primary first) — the KEK for provider configs, TSIG, HE keys."""

    admin_password_hash: SecretStr
    """argon2id hash seeding the bootstrap root credential (SPEC §6.3)."""

    session_secret: SecretStr
    """Starlette ``SessionMiddleware`` signing secret (SPEC §8.2)."""

    # --- M1 data-plane bootstrap (SPEC §16) ---
    bootstrap_path: str | None = None
    """Path to the KEK-encrypted TOML bootstrap file that seeds the M1 data plane.

    Required by the M1 data plane (``main()`` fail-fasts if unset, T-M1-26); the
    M2 database supersedes it as the source of keyring/routing.
    """

    metrics_port: int = 9090
    """Prometheus exposition port for the interim data-plane metrics server (SPEC §11.1)."""

    # --- Non-secret runtime configuration (SPEC §10.2) ---
    forwarded_allow_ips: str = "127.0.0.1"
    """nginx source IP/CIDR for uvicorn ``forwarded_allow_ips`` (SPEC §8.6)."""

    management_origin: str | None = None
    """Allowed browser origin (e.g. ``https://astropath.<domain>``) for the CSRF
    origin check on cookie-authenticated mutating requests (SPEC §8.4). When unset,
    the origin check is disabled (single-node dev); production sets it explicitly.
    """

    spa_dir: str | None = None
    """Directory of the built admin SPA (``index.html`` + ``assets/``), served by
    the management app behind an explicit catch-all (SPEC §9.3, T-M4-04). In the
    container this is ``/app/static`` (set via ``ASTROPATH_SPA_DIR``). When unset,
    or when the directory has no ``index.html``, the SPA is not served and the app
    still boots (API/ops only) — the dev workflow uses the Vite proxy instead.
    """

    dns_bind: str = "0.0.0.0"
    dns_port: int = 53
    http_bind: str = "0.0.0.0"
    http_port: int = 8080
    log_level: str = "INFO"
    log_format: str = "text"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a process-wide cached :class:`Settings` instance.

    Configuration is parsed once. Tests that need a fresh instance construct
    ``Settings(...)`` directly rather than calling this accessor.
    """
    return Settings()
