# astropath-dns-relay

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](./LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)

**A self-hosted, multi-backend ACME DNS-01 solver gateway.** astropath-dns-relay
presents an RFC2136 (DNS UPDATE) + TSIG front end that cert-manager's built-in
`rfc2136` DNS-01 solver talks to natively, and translates each DNS-01 challenge
into an API call against a pluggable DNS **provider backend** (Hurricane Electric
first, Route53 second). A FastAPI + Vite/React admin plane manages backends and
domain routing.

It exists to issue wildcard `*.<domain>` Let's Encrypt certificates (DNS-01 is
mandatory for wildcards) without handing a cloud DNS credential to every cluster —
the gateway holds the provider credential and exposes only the narrow
`_acme-challenge` TXT write surface.

## Key properties

- **Write-path only.** The gateway never serves authoritative DNS to the internet
  and is never publicly reachable. cert-manager's propagation self-check and Let's
  Encrypt's validation both query the *provider's* real public nameservers, which
  already serve the pushed record. astropath-dns-relay only makes outbound API calls.
- **A valid TSIG is not a zone-write credential.** After TSIG verification, a hard
  allowlist accepts only ADD/DELETE of a TXT rrset named exactly
  `_acme-challenge.<managed-zone>` — anything else is REFUSED.
- **Single-admin management plane.** Secrets are generated in-panel, shown once,
  and stored encrypted (KEK/MultiFernet) or one-way hashed (argon2id / SHA-256).
- **Pluggable providers.** Adding a provider is one file plus one registry entry;
  its `config_schema()` drives both API validation and the SPA credential form.

## Architecture

Two planes run in **one asyncio process, one container**, under independent
per-plane supervisors (a crash in one plane never cancels the other):

```
              ┌──────────── astropath (one container, one asyncio loop) ─────────────┐
 cert-manager │  DATA PLANE  (supervisor A)                                           │
 (rfc2136) ──UPDATE+TSIG──▶ Rfc2136Server (UDP + TCP)                                  │
              │      │ verify TSIG → assert UPDATE → allowlist _acme-challenge TXT     │
              │      ▼                                                                  │
              │  Dispatcher ─ zone→backend (in-mem cache, DB source) ─▶ provider.push  │
 admin ──HTTPS─▶ MANAGEMENT PLANE (supervisor B)                       │ httpx / aws   │
 (nginx TLS)  │  uvicorn(app, lifespan="off"): /api/v1 + Vite SPA      │               │
              │      │ require_admin (cookie OR X-API-Key)             │               │
              │      ▼                                                  │               │
              │  AsyncSession (asyncpg → Postgres, encrypted creds) ◀───┘               │
              └──────────────────────────────────────────────────────────────────────┘
                          │ outbound HTTPS   ▼
                  Hurricane Electric / Route53  ◀── Let's Encrypt validates here
```

The authoritative design is [SPEC.md](./SPEC.md); the task breakdown is
[TASKS.md](./TASKS.md).

## Providers

| Provider | Backend | Notes |
|---|---|---|
| Hurricane Electric | `POST https://dyn.dns.he.net/nic/update` | Single value per dynamic record; per-record key is domain-scoped; `cleanup()` overwrites a placeholder (HE has no delete). Record must be pre-created and flagged dynamic in the HE dashboard. |
| Route53 | `aiobotocore` | UPSERT present, read-then-DELETE cleanup, multi-value TXT. Scope the IAM policy to `_acme-challenge`/TXT/UPSERT+DELETE — see [docs/route53-iam.md](./docs/route53-iam.md). |

## Quickstart (local development)

Requires Docker and [uv](https://docs.astral.sh/uv/). This runs the gateway plus a
throwaway Postgres — it is **not** the deployment artifact (production is the
Ansible `fw-astropath` stack; see below).

```bash
# 1. Install the toolchain and dependencies
uv sync --frozen

# 2. Generate bootstrap secrets (each is shown ONCE — store them vaulted).
uv run python -m astropath.bootstrap gen-kek          # -> ASTROPATH_CREDENTIAL_KEK
#   admin password hash (argon2id) and session secret are generated out-of-band.

# 3. Copy the env template and fill in PLACEHOLDER values (no real secrets in git)
cp .env.example .env.local        # then edit real values into .env.local
#   point docker-compose.example.yml's env_file at .env.local, or edit in place.

# 4. Build and run (remap host port 53 if a local resolver already binds it)
docker compose -f docker-compose.example.yml up --build

# Validate the compose file without running:
docker compose -f docker-compose.example.yml config
```

Probes and scrape once it is up:

```bash
curl -s localhost:8080/healthz     # liveness (process up)
curl -s localhost:8080/readyz      # per-plane readiness (DNS sockets/keyring/cache; API=DB)
curl -s localhost:8080/metrics     # Prometheus exposition (LAN-only in production)
```

## Bootstrap CLI walkthrough (M1, no database)

M1 issues the wildcard certificate from a file/env bootstrap before the DB/API/SPA
exist. All values below are placeholders.

```bash
# A KEK is required to encrypt the bootstrap file's secrets at rest.
export ASTROPATH_CREDENTIAL_KEK="$(uv run python -m astropath.bootstrap gen-kek)"

# Write a starter bootstrap file. This mints a TSIG key and reveals its secret
# ONCE (base64 BIND form) — that exact string goes into the cert-manager Secret.
uv run python -m astropath.bootstrap init \
  --output astropath.bootstrap.toml \
  --zone example.com. \
  --record-name _acme-challenge.example.com. \
  --provider hurricane \
  --he-key "<HE-DYNAMIC-KEY-PLACEHOLDER>"        # from the HE dashboard, pre-created + dynamic

# Emit the matching cert-manager TSIG Secret (stringData — never hand-encode .data,
# which double-base64s to BADKEY). Use the base64 secret 'init' printed once.
uv run python -m astropath.bootstrap secret-yaml \
  --secret "<TSIG-SECRET-PLACEHOLDER-shown-once-by-init>"
```

Point the service at the file with `ASTROPATH_BOOTSTRAP_PATH=astropath.bootstrap.toml`.
A lost one-time secret is never redisplayed — **revoke and recreate**.

Once the store lands (M2+), migrate the file into Postgres and retire it:

```bash
uv run python -m astropath.migrate_bootstrap --bootstrap astropath.bootstrap.toml
```

## Configuration

Only bootstrap secrets live in the environment (SPEC §10.2); all arrive
ansible-vault'd in production. See [.env.example](./.env.example) for the full set:

| Env var | Purpose |
|---|---|
| `ASTROPATH_DATABASE_DSN` | `postgresql+asyncpg://…` (async driver scheme) |
| `ASTROPATH_CREDENTIAL_KEK` | Ordered Fernet keylist (primary first) — the KEK |
| `ASTROPATH_ADMIN_PASSWORD_HASH` | argon2id hash seeding the admin credential |
| `ASTROPATH_SESSION_SECRET` | Starlette session-cookie signing secret |
| `ASTROPATH_BOOTSTRAP_PATH` | Path to the M1 bootstrap file |
| `ASTROPATH_FORWARDED_ALLOW_IPS` | nginx source IP/CIDR for uvicorn proxy headers |
| `ASTROPATH_DNS_BIND` / `_DNS_PORT` | RFC2136 listener (UDP+TCP) |
| `ASTROPATH_HTTP_BIND` / `_HTTP_PORT` | Management API / SPA |
| `ASTROPATH_SHUTDOWN_DRAIN_TIMEOUT` | Seconds to drain in-flight dispatches on SIGTERM |
| `ASTROPATH_LOG_LEVEL` / `_LOG_FORMAT` | Logging (`text` or `json`) |

TSIG keys and API tokens are **not** env vars — they are generated in the panel and
stored encrypted/hashed (or in the M1 bootstrap file).

## Observability

- **Metrics** at `/metrics` (LAN-only): challenge outcomes, provider-call latency,
  TSIG failures by reason, a dedicated BADTIME counter, per-zone last-success
  timestamp, per-plane restarts, and the per-plane unhealthy gauge (SPEC §11.1).
- **Probes:** `/healthz` (liveness) and `/readyz` (per-plane readiness — DNS
  sockets bound + keyring loaded + routing cache populated; API = DB reachable).
- **Correlation ids** thread one id through a challenge's whole lifecycle (logs +
  the `X-Correlation-ID` response header). Logs are redacted: secret-shaped field
  names and values (DSN, env, header, base64-key shapes) never reach stdout.
- Diagnosing a stuck challenge: [docs/he-propagation-diagnostics.md](./docs/he-propagation-diagnostics.md).

## Deployment

Production is an Ansible `docker-compose-service` stack behind nginx TLS with an
externally-managed Postgres and firewalling (UDP+TCP on the RFC2136 port):

- Kubernetes / cert-manager wiring and bring-up: [deploy/k8s/](./deploy/k8s/) and
  its [RUNBOOK.md](./deploy/k8s/RUNBOOK.md).
- Host / Ansible deploy: [deploy/ansible/](./deploy/ansible/) and its
  [README.md](./deploy/ansible/README.md) + [host_prerequisites.md](./deploy/ansible/host_prerequisites.md).
- **cert-manager traps to get right:** set `tsigAlgorithm: HMACSHA256` explicitly
  (default is HMACMD5 → silent BADKEY); create the TSIG Secret with `--from-literal`
  (never a hand-encoded `.data`); point the DNS-01 self-check at public recursive
  resolvers in split-horizon setups; require host NTP (skew → BADTIME).

## Runbooks & docs

- [docs/kek-rotation-runbook.md](./docs/kek-rotation-runbook.md) — KEK rotation +
  backup/restore.
- [docs/he-propagation-diagnostics.md](./docs/he-propagation-diagnostics.md) —
  provider-push vs public-visibility triage.
- [docs/route53-iam.md](./docs/route53-iam.md) — least-privilege Route53 IAM policy.
- [deploy/k8s/RUNBOOK.md](./deploy/k8s/RUNBOOK.md) — cert-manager bring-up and
  challenge diagnosis.

## Development

```bash
uv sync --frozen
uv run ruff check .        # lint
uv run black --check .     # format check
uv run mypy                # strict type check
uv run pytest              # tests (Postgres-backed suites use testcontainers)
```

## License

astropath-dns-relay is licensed under **GPL-3.0-or-later** (SPDX
`GPL-3.0-or-later`). The full text is in [LICENSE](./LICENSE); every source file
carries the short GPLv3 header (Copyright (C) 2026 Saad Ali). The `frontend/`
inherits the same license; third-party licenses of the built SPA bundle are
recorded in [THIRD-PARTY](./THIRD-PARTY).
