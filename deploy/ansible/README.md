# Gateway-host deployment examples (`deploy/ansible/`)

**EXAMPLE / TEMPLATE artifacts only.** This public repo ships the *shape* of the
gateway-host deployment; the **private ops repo instantiates it** with real
inventory, ansible-vault secret values, TLS material, and its own role
implementations. No real hostname, IP, port, or secret ever appears here.

astropath-dns-relay runs on a LAN gateway host as the `fw-astropath`
docker-compose stack (SPEC §1.4, §15.4), fronted by host nginx (LAN TLS) and
host nftables (source-restricted RFC2136 port). The Kubernetes / cert-manager
side lives in `deploy/k8s/` (authored separately) -- cross-referenced below.

## What the PRIVATE ops repo supplies

| Concern | Owner |
|---|---|
| Inventory, real host/group names, `astropath_gateway` group membership | private repo |
| `ansible-vault`-encrypted secret **values** for every `vault_astropath_*` name | private repo |
| The `docker-compose-service`, `pgsql_dbs_users`, `nginx`, and `nftables` roles | private repo |
| LAN wildcard TLS certificate + key | private repo |
| The KEK-encrypted M1 bootstrap file (`astropath.bootstrap.toml`, SPEC §16) | private repo (vault-delivered) |
| Concrete published image tag | private repo (pins it) |

## What THIS tree provides

| File | Purpose | Task |
|---|---|---|
| `templates/fw-astropath.compose.yml.j2` | The `docker-compose-service` stack (app only; Postgres is host-managed) | T-DEPLOY-07 |
| `templates/astropath.nginx.conf.j2` | `astropath.<domain>` LAN TLS vhost + proxy-header contract (SPEC §2/§8.6) | T-DEPLOY-07 |
| `group_vars/astropath_gateway/vars.example.yml` | Non-secret role inputs (incl. the `pgsql_dbs_users` entry) | T-DEPLOY-07 |
| `group_vars/astropath_gateway/vault.example.yml` | The `vault_astropath_*` variable **names** (placeholder values) | T-DEPLOY-07 |
| `templates/astropath.nftables.nft.j2` | RFC2136 port open (UDP+TCP), source-restricted (SPEC §14.7) | T-DEPLOY-08 |
| `host_prerequisites.md` | NTP/chrony, port selection, firewall, DNS A-record host prereqs | T-DEPLOY-08 |

## Illustrative play (the private repo owns the real one)

```yaml
# ILLUSTRATIVE ONLY. Role names/var interfaces belong to the private ops repo.
- hosts: astropath_gateway
  become: true
  roles:
    - role: pgsql_dbs_users         # provisions db+user from `postgresql_db_users`
    - role: docker-compose-service  # renders fw-astropath.compose.yml.j2, runs `docker compose up -d`
    - role: nginx                   # renders astropath.nginx.conf.j2, `nginx -t` then reload
    - role: nftables                # renders astropath.nftables.nft.j2 (open-port, source-restricted)
```

The `docker-compose-service` role owns where it writes the rendered compose file
and how it wires the environment; this repo only provides the template content it
renders. Everything under `environment:` in the compose template resolves from
`vars.example.yml` (non-secret) and the vault (secret) at render time.

## The proxy-header pairing (do not skip)

nginx sets `X-Forwarded-Proto/-For/Host`; uvicorn trusts them **only** from
`ASTROPATH_FORWARDED_ALLOW_IPS` (SPEC §8.6). The compose template fixes the
docker network subnet so the source IP uvicorn observes for nginx is the network
gateway (`.1`); set `astropath_forwarded_allow_ips` to that address. Miss this
and Secure cookies + https scheme detection silently break behind TLS.

## Host prerequisites (T-DEPLOY-08)

Before first deploy, satisfy `host_prerequisites.md`: host NTP/chrony (TSIG skew
> 300s fudge -> 100% BADTIME), the non-53 RFC2136 port decision, the firewall
source restriction (Cilium masquerade caveat), the `astropath.<domain>` DNS
A-record, the host-Postgres listen/`pg_hba` reachability from the container
subnet, the bootstrap file's readability by the container uid (`10001`), and the
`$$`-escaping of the argon2 admin hash wherever it passes through Docker Compose.

## References

- `SPEC.md` §15.4 (Ansible/host deploy), §8.6/§2 (proxy headers), §14.7
  (firewall UDP+TCP + Cilium masquerade), §11 (BADTIME/NTP), §16 (M1 bootstrap).
- Repo-root `docker-compose.example.yml` + `.env.example` -- the dev-only stack
  these production examples stay consistent with.
- `deploy/k8s/` -- cert-manager ClusterIssuer, TSIG Secret, egress/NetworkPolicy,
  and the split-horizon self-check flags (the cluster side of this deployment).
