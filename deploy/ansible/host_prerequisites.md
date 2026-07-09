# Gateway-host prerequisites (T-DEPLOY-08)

Host-level requirements the private ops repo must satisfy on the LAN gateway
before the `fw-astropath` stack (T-DEPLOY-07) can issue certificates. Every value
is a placeholder; real hostnames/IPs/ports live only in the private repo.

## 1. RFC2136 listener port (UDP **and** TCP)

The gateway already runs Pi-hole (`53`) and PowerDNS-auth (`5300`). The
astropath-dns-relay RFC2136 listener therefore uses a **non-53 port `<dns-port>`**,
set via `ASTROPATH_DNS_PORT` (overrides the image default) and consumed by the
compose ports + the nftables template.

- **Operator decision pending:** choose `<dns-port>` avoiding `53` (Pi-hole) and
  `5300` (PowerDNS-auth), and any other listener on this host. The example vars
  file uses `5301` as a placeholder.
- **Open BOTH protocols.** TSIG-signed UPDATEs can exceed 512 bytes and fall back
  to TCP (SPEC §14.7); a UDP-only rule yields intermittent, hard-to-diagnose
  failures. `cert-manager`'s rfc2136 `nameserver` is `<gateway-ip>:<dns-port>`.
- If `<dns-port> < 1024`, the container needs `NET_BIND_SERVICE` (granted in the
  compose template); a port >= 1024 needs no capability -- the private repo may
  drop the cap once the port is finalized.

## 2. Firewall source restriction (nftables)

Render `templates/astropath.nftables.nft.j2` via the private repo's nftables /
open-port role. It allows `<dns-port>` udp+tcp only from
`astropath_acme_client_cidrs` and drops all other traffic to that port.

**Cilium masquerade caveat (SPEC §14.7)** -- the correct source range depends on
the cluster's routing mode:

| Cilium mode | cert-manager egress source | `astropath_acme_client_cidrs` holds |
|---|---|---|
| default masquerade | SNAT'd to the **node** IPs | the node IPs / node subnet |
| native routing / masquerade disabled | the **pod** IP | the pod CIDR |

Confirm the mode against the cluster and populate accordingly. This mirrors the
egress/NetworkPolicy allowances documented in the `deploy/k8s/` runbook (which
also opens cert-manager egress to `<gateway-ip>:<dns-port>`, the public recursive
resolvers, and Let's Encrypt `:443`). Keep both sides in agreement.

## 3. Host clock / NTP -- **required** (BADTIME)

TSIG carries a signing time checked against a **fudge of 300 s** (SPEC §3.5).
Clock skew beyond the fudge yields **BADTIME** on every UPDATE -> **100% issuance
failure**, signed but rejected (SPEC §11 / HIGH-2). The container **inherits the
host clock** (no independent clock source), so the host must be time-synced.

- Run **chrony** (or systemd-timesyncd / ntpd) on the gateway and confirm it is
  synchronized before deploy:
  - `chronyc tracking` -> `Leap status : Normal`, small `System time` offset; or
  - `timedatectl` -> `System clock synchronized: yes`, `NTP service: active`.
- No per-container NTP is needed or wanted -- do not add one; fix the host.
- **Alerting:** wire the `astropath_tsig_badtime_total` counter (SPEC §11.1,
  T-M1-27) into the monitoring stack. Any nonzero rate means clock skew (or a
  key/algorithm mismatch) -- treat as page-worthy: certificates stop renewing.

## 4. DNS A-record for the admin vhost

Publish `astropath.<domain>` -> `<gateway-ip>` (A record) via the **existing
PowerDNS tooling** on this gateway, so the nginx vhost (`astropath.nginx.conf.j2`)
is reachable on the LAN. This is the management/admin plane only; it is unrelated
to the RFC2136 write-path and never faces the WAN (SPEC §1.1, §8.7).

## 5. Host-managed Postgres reachable from the container

Postgres is provisioned on the host by the `pgsql_dbs_users` role (db + user
`astropath`, SPEC §15.4) -- it is **not** in the compose stack. The container
reaches it via `host.docker.internal` (mapped through `extra_hosts: host-gateway`
in the compose template) or the docker bridge gateway. Ensure:

- Postgres `listen_addresses` includes the docker bridge interface (not only
  `localhost`), and
- `pg_hba.conf` permits the `astropath` user from the fw-astropath docker subnet
  (`astropath_docker_subnet`), and
- the password embedded in `vault_astropath_database_dsn` matches
  `vault_astropath_db_password` used by `pgsql_dbs_users`.

Note: the DB is the **sole config source** -- keyring, provider routing, and TSIG
keys all live in Postgres (SPEC §10). The relay does not serve without it, so
provision Postgres before first deploy.

## 6. Compose `$`-escaping of the argon2 admin hash

A container-runtime trap that crash-loops the stack before it serves a single
request. It bites from-scratch first boots and is easy to miss.

Docker Compose interpolates `$...` sequences in the values it loads. An argon2id
hash is dense with `$` (`$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>`), so when
`ASTROPATH_ADMIN_PASSWORD_HASH` arrives through a compose `env_file` -- the dev
stack's `docker-compose.example.yml` uses `env_file: - .env.example` -- each
`$argon2id`, `$v`, `$m`, ... is consumed as an **unset variable** and the hash
reaches the app mangled (fields dropped), so **admin login silently fails**.

Double every `$` as `$$` in the env file so Compose passes the literal hash:

- Wrong: `ASTROPATH_ADMIN_PASSWORD_HASH=$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>`
- Right: `ASTROPATH_ADMIN_PASSWORD_HASH=$$argon2id$$v=19$$m=65536,t=3,p=4$$<salt>$$<hash>`

The production template (`templates/fw-astropath.compose.yml.j2`) sources secrets
from ansible-vault into the `environment:` map rather than an `env_file`, but
Compose interpolates `environment:` values too -- whatever renders into the
compose file must already have its `$` doubled, so the private repo applies the
same `$$`-escaping to `vault_astropath_admin_password_hash` (or in its
`docker-compose-service` role) before `docker compose up`.
