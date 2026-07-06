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

"""M1-REQUIRED cert-manager/miekg reply-TSIG contract test (T-TEST-09).

cert-manager's rfc2136 DNS-01 solver is built on Go's github.com/miekg/dns, and
that client VERIFIES THE TSIG SIGNATURE ON THE REPLY. An unsigned or badly-signed
reply fails inside miekg (``ErrNoSig`` / bad authentication), cert-manager treats
the UPDATE as failed, and the certificate never issues even though the TXT record
landed. This behavior is source-level, unprovable from documentation, and a
dnspython-vs-dnspython round-trip lenient-agrees and HIDES it (SPEC §13.2). So the
gate is a REAL miekg/dns client, not another dnspython client.

This wiring boots the assembled astropath data plane in-process on an ephemeral
port with a :class:`FakeProvider` (mirroring the M1 acceptance suites), builds the
Go client under ``tests/contract/miekgclient/``, runs the cert-manager-shaped
sequence over both UDP and TCP, and asserts the machine-readable JSON verdicts.

The load-bearing assertion for every signed exchange is BOTH:

* ``reply_had_tsig is True`` — the reply is signed at all (catches an unsigned
  reply; miekg only runs TSIG verification when the reply itself carries a TSIG,
  so this flag, not the absence of an error, is what catches the interop bug), and
* ``reply_tsig_valid is True`` — miekg's own independent HMAC recomputation
  accepts astropath's MAC bytes (catches a MAC a dnspython-only test would accept).

If ``go`` is absent the test skips with an explicit reason (CI must install go).
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import shutil
import subprocess
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from prometheus_client import CollectorRegistry
from tests._fakes import FakeProvider, routing_for

from astropath.data_plane.dispatcher import Dispatcher
from astropath.data_plane.server import Rfc2136Server
from astropath.data_plane.tsig import TsigKeySpec, build_keyring
from astropath.observability import DataPlaneMetrics

# Throwaway TSIG identity. No real secret exists in this repo (SPEC secret
# discipline); this material is generated for the test only and never logged.
KEYNAME = "cm-key."
SECRET_B64 = base64.b64encode(b"0123456789abcdef0123456789abcdef").decode()
WRONG_SECRET_B64 = base64.b64encode(b"WRONGwrongWRONGwrongWRONGwrong32").decode()
# A realistic ACME DNS-01 token (43-char base64url SHA-256 digest shape).
TOKEN = "Vv8kAx_1qz3nQ2rJ5tXbC9dwE7fLmN0pR4sU6yZ8aQk"
ZONE = "example.com."
FQDN = "_acme-challenge.example.com."

CLIENT_DIR = Path(__file__).parent / "miekgclient"

# The signed add/delete run over BOTH transports; each add hits present(), each
# delete (class NONE) hits cleanup(). The negative controls never dispatch.
SIGNED_UPDATE_SCENARIOS = ("udp_add", "udp_delete", "tcp_add", "tcp_delete")


class _Harness:
    """A running in-process astropath server plus its recording provider."""

    def __init__(self, server: Rfc2136Server, provider: FakeProvider) -> None:
        self.server = server
        self.provider = provider

    @property
    def port(self) -> int:
        return self.server.port


@pytest.fixture(scope="session")
def go_client(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build the miekg/dns contract client once; skip cleanly if go is absent."""
    if shutil.which("go") is None:
        pytest.skip(
            "go toolchain not available — T-TEST-09 needs go to build the "
            "miekg/dns interop client (CI: install go >= 1.24)"
        )
    binary = tmp_path_factory.mktemp("miekgclient") / "miekgclient"
    build = subprocess.run(
        ["go", "build", "-o", str(binary), "."],
        cwd=CLIENT_DIR,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    if build.returncode != 0:
        pytest.fail(
            "go build of the miekg/dns contract client failed:\n"
            f"stdout:\n{build.stdout}\nstderr:\n{build.stderr}"
        )
    return binary


@pytest.fixture
async def harness() -> AsyncIterator[_Harness]:
    """Boot the assembled data plane on 127.0.0.1:0 with a FakeProvider.

    Mirrors the M1 acceptance-test boot pattern (test_accept_tsig_roundtrip): the
    server serves in the running loop while the external Go client connects over a
    real loopback socket from a worker thread.
    """
    keyring = build_keyring([TsigKeySpec(KEYNAME, "hmac-sha256", SECRET_B64)])
    provider = FakeProvider()
    dispatcher = Dispatcher(
        routing_for(provider), DataPlaneMetrics(registry=CollectorRegistry())
    )
    server = Rfc2136Server(
        keyring,
        dispatcher,
        DataPlaneMetrics(registry=CollectorRegistry()),
        host="127.0.0.1",
        port=0,
    )
    ready = asyncio.Event()
    task = asyncio.create_task(server.serve(ready=ready))
    await asyncio.wait_for(ready.wait(), timeout=5.0)
    try:
        yield _Harness(server, provider)
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


def _invoke_client(binary: Path, server_addr: str) -> subprocess.CompletedProcess[str]:
    """Run the Go client (blocking) against ``server_addr``; offloaded to a thread."""
    return subprocess.run(
        [
            str(binary),
            "-server",
            server_addr,
            "-keyname",
            KEYNAME,
            "-secret",
            SECRET_B64,
            "-wrongsecret",
            WRONG_SECRET_B64,
            "-algorithm",
            "hmac-sha256.",
            "-zone",
            ZONE,
            "-fqdn",
            FQDN,
            "-token",
            TOKEN,
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


async def _run_client(binary: Path, server_addr: str) -> tuple[dict[str, Any], int]:
    """Run the client without blocking the server loop; return (report, exit)."""
    proc = await asyncio.to_thread(_invoke_client, binary, server_addr)
    if not proc.stdout.strip():
        pytest.fail(
            f"miekg client produced no JSON (exit={proc.returncode}):\n"
            f"stderr:\n{proc.stderr}"
        )
    report: dict[str, Any] = json.loads(proc.stdout)
    return report, proc.returncode


async def test_miekg_client_accepts_astropath_signed_replies(
    harness: _Harness, go_client: Path
) -> None:
    report, exit_code = await _run_client(go_client, f"127.0.0.1:{harness.port}")

    scenarios: dict[str, dict[str, Any]] = {
        str(s["name"]): s for s in report["scenarios"]
    }

    # A real miekg/dns is linked (not a stubbed "unknown" build).
    assert str(report["miekg_version"]).startswith("v1."), report["miekg_version"]

    # Every scenario passes by the client's own verdict; exit 0 == all pass.
    assert report["all_pass"] is True, report
    assert exit_code == 0, report
    for name, scenario in scenarios.items():
        assert scenario["pass"] is True, (name, scenario)

    # Load-bearing, independently re-checked: signed replies (add/delete over UDP
    # and TCP) BOTH carry a TSIG and VERIFY under miekg's HMAC. reply_had_tsig
    # catches an unsigned reply; reply_tsig_valid catches a MAC miekg rejects.
    for name in SIGNED_UPDATE_SCENARIOS:
        scenario = scenarios[name]
        assert scenario["rcode"] == "NOERROR", (name, scenario)
        assert scenario["reply_had_tsig"] is True, (name, scenario)
        assert scenario["reply_tsig_valid"] is True, (name, scenario)
        assert scenario["exchange_error"] == "", (name, scenario)

    # Negative control (a): an UNSIGNED UPDATE is refused NOTAUTH by the auth gate,
    # and the reply to an unsigned request is itself unsigned — assert rcode.
    unsigned = scenarios["unsigned_update"]
    assert unsigned["rcode"] == "NOTAUTH", unsigned
    assert unsigned["reply_had_tsig"] is False, unsigned

    # Negative control (b): a signed SOA QUERY is REFUSED (no SOA answering in M1),
    # and — being a reply to a signed request — the REFUSED reply is TSIG-signed
    # and verifies, proving policy replies are signed too.
    soa = scenarios["soa_query_signed"]
    assert soa["rcode"] == "REFUSED", soa
    assert soa["reply_had_tsig"] is True, soa
    assert soa["reply_tsig_valid"] is True, soa

    # Negative control (c): an UPDATE signed with the WRONG secret is NOTAUTH; the
    # server signs a BADSIG error reply with the correct key (the client, holding
    # the wrong key, cannot verify it — an expected reply verify error).
    wrong = scenarios["wrong_key_update"]
    assert wrong["rcode"] == "NOTAUTH", wrong
    assert wrong["tsig_error_field"] == "BADSIG", wrong

    # Cross-check the wire semantics reached the dispatcher: the miekg-signed add
    # hit present() with the raw token and the class-NONE delete hit cleanup(),
    # over both UDP and TCP; the three negative controls never dispatched.
    assert harness.provider.present_calls == [
        (ZONE, FQDN, (TOKEN,)),
        (ZONE, FQDN, (TOKEN,)),
    ]
    assert harness.provider.cleanup_calls == [
        (ZONE, FQDN, (TOKEN,)),
        (ZONE, FQDN, (TOKEN,)),
    ]
