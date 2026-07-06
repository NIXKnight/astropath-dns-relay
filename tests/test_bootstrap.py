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

"""M1 bootstrap loader tests (T-M1-21, SPEC §16)."""

from __future__ import annotations

import base64
from pathlib import Path
from urllib.parse import parse_qs

import dns.message
import dns.name
import dns.rcode
import dns.update
import httpx
import pytest
from prometheus_client import CollectorRegistry

from astropath.bootstrap import BootstrapError, build_data_plane, load_bootstrap
from astropath.crypto import Kek, generate_key
from astropath.data_plane.dispatcher import Dispatcher
from astropath.observability import DataPlaneMetrics
from astropath.providers.hurricane import HurricaneProvider

_TSIG_SECRET = base64.b64encode(b"0123456789abcdef0123456789abcdef").decode()
_HE_KEY = "THROWAWAY-he-dynamic-key"


def _write_bootstrap(path: Path, kek: Kek) -> None:
    tsig_token = kek.encrypt_str(_TSIG_SECRET)
    he_token = kek.encrypt_str(_HE_KEY)
    path.write_text(
        "[listener]\n"
        'host = "127.0.0.1"\n'
        "port = 5353\n\n"
        "[[tsig_keys]]\n"
        'name = "cm-key."\n'
        'algorithm = "hmac-sha256"\n'
        f'secret = "{tsig_token}"\n\n'
        "[[zones]]\n"
        'zone = "example.com."\n'
        'provider = "hurricane"\n'
        'record_name = "_acme-challenge.example.com."\n'
        f'he_dynamic_key = "{he_token}"\n',
        encoding="utf-8",
    )


def test_load_bootstrap_decrypts_secrets(tmp_path: Path) -> None:
    kek = Kek([generate_key()])
    path = tmp_path / "astropath.bootstrap.toml"
    _write_bootstrap(path, kek)

    config = load_bootstrap(path, kek)

    assert config.listener_host == "127.0.0.1"
    assert config.listener_port == 5353
    assert config.tsig_keys[0].name == "cm-key."
    assert config.tsig_keys[0].secret_b64 == _TSIG_SECRET  # decrypted
    assert config.zones[0].zone == "example.com."
    assert config.zones[0].he_dynamic_key == _HE_KEY  # decrypted


def test_missing_file_raises(tmp_path: Path) -> None:
    kek = Kek([generate_key()])
    with pytest.raises(FileNotFoundError):
        load_bootstrap(tmp_path / "nope.toml", kek)


def test_malformed_toml_raises(tmp_path: Path) -> None:
    kek = Kek([generate_key()])
    path = tmp_path / "bad.toml"
    path.write_text("this is = = not toml", encoding="utf-8")
    with pytest.raises(BootstrapError):
        load_bootstrap(path, kek)


async def test_build_data_plane_serves_from_file(tmp_path: Path) -> None:
    kek = Kek([generate_key()])
    path = tmp_path / "astropath.bootstrap.toml"
    _write_bootstrap(path, kek)
    config = load_bootstrap(path, kek)

    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, text="good")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    runtime = build_data_plane(config, http_client=client)

    # keyring + routing built as the runtime objects M2 will also produce
    assert dns.name.from_text("cm-key.") in runtime.keyring
    assert runtime.routing.match(dns.name.from_text("example.com.")) is not None
    assert isinstance(runtime.providers[0], HurricaneProvider)

    # Dispatch a present through the runtime; the injected HE key is used.
    dispatcher = Dispatcher(
        runtime.routing, DataPlaneMetrics(registry=CollectorRegistry())
    )
    u = dns.update.UpdateMessage("example.com.")
    u.add("_acme-challenge.example.com.", 300, "TXT", "token123")
    msg = dns.message.from_wire(u.to_wire())
    assert isinstance(msg, dns.update.UpdateMessage)

    rcode = await dispatcher.dispatch(msg, source="1.2.3.4")
    assert rcode == dns.rcode.NOERROR
    form = {k: v[0] for k, v in parse_qs(captured[0].content.decode()).items()}
    assert form["password"] == _HE_KEY  # per-record key injected from the file
    assert form["txt"] == "token123"
