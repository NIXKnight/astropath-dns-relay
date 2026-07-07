# AstropathDNSRelay -- cert-manager bring-up runbook

Task: T-DEPLOY-09 (HIGH-10, BLOCKER-3). Covers SPEC 14. This runbook takes an
operator from a fresh cluster to a Let's Encrypt wildcard `*.<domain>` cert that
Traefik serves, and gives a diagnostics tree for a stuck challenge.

The AstropathDNSRelay service runs **outside** the cluster (a LAN gateway host,
Ansible-deployed -- T-DEPLOY-07/08). The cluster side is only cert-manager
talking RFC2136/TSIG to that gateway. This runbook is the cluster half.

## File map (`deploy/k8s/`)

| File | Purpose | Namespace |
|---|---|---|
| `cert-manager/helm-values.cert-manager.yaml` | controller `extraArgs` -- split-horizon self-check fix (BLOCKER-3) | (Helm release) |
| `cert-manager/tsig-secret.example.yaml` | TSIG Secret (`stringData`) | `cert-manager` (cluster-resource ns) |
| `cert-manager/clusterissuer-letsencrypt-staging.yaml` | rfc2136 ClusterIssuer, ACME staging | cluster-scoped |
| `cert-manager/clusterissuer-letsencrypt-prod.yaml` | rfc2136 ClusterIssuer, ACME prod | cluster-scoped |
| `cert-manager/networkpolicy-cert-manager-egress.yaml` | egress allow-list (default-deny clusters) | `cert-manager` |
| `traefik/certificate-wildcard.yaml` | wildcard Certificate + TLS Secret | `<traefik-namespace>` |
| `validate.sh` | offline structural + kubeconform schema validation | -- |

Substitute every `<placeholder>` from the private ops repo. Real IPs, domains,
and secrets never live in this repo.

## Placeholders

`<gateway-ip>` gateway LAN IP (literal) · `<dns-port>` RFC2136 listener port ·
`<tsig-key-name>` server TSIG key name (default `astropath-tsig.`, trailing dot) ·
`<domain>` apex zone · `<traefik-namespace>` Traefik workload ns ·
`<your-email>` ACME contact · `<TSIG-SECRET-BASE64>` base64 BIND secret ·
`<kube-apiserver-ip>` API server address reachable from pods.

---

## 0. Prerequisites

1. **Gateway deployed and reachable** (Ansible, T-DEPLOY-07). The RFC2136 listener
   answers on `<gateway-ip>:<dns-port>` over **both UDP and TCP**. Firewall
   (nftables, T-DEPLOY-07) opens both protocols, source-scoped to the cluster
   (node IPs vs pod CIDR per Cilium masquerade mode -- SPEC 14.7).
2. **Host NTP synced** (T-DEPLOY-08). TSIG signatures carry a timestamp; skew
   beyond the fudge (300s) makes **every** UPDATE fail BADTIME. Verify the
   gateway host and the cert-manager nodes are NTP-synced before issuing.
3. **Hurricane Electric record pre-created** (SPEC 5.7). HE has no
   create-on-write. In the HE dashboard, for the target zone:
   - create the `_acme-challenge.<domain>` TXT record,
   - flag it **dynamic**,
   - mint its **per-record dynamic key**.
   That key goes into the gateway's bootstrap config (domain-scoped, HIGH-7),
   **not** into any cluster manifest.
4. **TSIG key minted** by `astropath-bootstrap gen-tsig` (secret shown once,
   base64 BIND form). The same base64 string feeds the gateway and the cluster
   Secret -- they must key identically.
5. **cert-manager CRDs + controller installable** via Helm (`jetstack/cert-manager`).

Validate the manifests locally before applying (no cluster needed):

```
deploy/k8s/validate.sh
```

---

## 1. Install cert-manager with the split-horizon fix (BLOCKER-3)

```
helm repo add jetstack https://charts.jetstack.io && helm repo update
helm upgrade --install cert-manager jetstack/cert-manager \
  --namespace cert-manager --create-namespace \
  --set crds.enabled=true \
  --values deploy/k8s/cert-manager/helm-values.cert-manager.yaml
```

`helm-values.cert-manager.yaml` sets `--dns01-recursive-nameservers-only` +
`--dns01-recursive-nameservers=1.1.1.1:53,8.8.8.8:53`. Without this, a
split-horizon homelab resolves the **internal** view of `<domain>`, never sees
HE's public `_acme-challenge` TXT, and the challenge hangs `pending` forever.

Confirm the flags landed on the controller:

```
kubectl -n cert-manager get deploy cert-manager \
  -o jsonpath='{.spec.template.spec.containers[0].args}' | tr ',' '\n' | grep recursive
```

## 2. Create the TSIG Secret (cluster-resource namespace)

Preferred -- keep the plaintext out of git (SPEC 14.5):

```
kubectl -n cert-manager create secret generic tsig-secret \
  --from-literal=tsig-secret-key='<TSIG-SECRET-BASE64>'
```

GitOps alternative: `tsig-secret.example.yaml` with the value injected by a
sealed-secrets / SOPS / ExternalSecrets layer -- never a plaintext secret in git.

**Double-base64 trap (SPEC 14.5):** always use `--from-literal` or `stringData`.
Never put an already-base64 value under `.data`; Kubernetes base64-encodes it
again -> BADKEY/BADSIG on every UPDATE. Verify the stored value round-trips to
the BIND base64 string you minted:

```
kubectl -n cert-manager get secret tsig-secret \
  -o jsonpath='{.data.tsig-secret-key}' | base64 -d
# must equal the base64 BIND secret from astropath-bootstrap (single-encoded)
```

## 3. Apply the ClusterIssuers

```
kubectl apply -f deploy/k8s/cert-manager/clusterissuer-letsencrypt-staging.yaml
kubectl apply -f deploy/k8s/cert-manager/clusterissuer-letsencrypt-prod.yaml
kubectl get clusterissuer   # both should report READY=True (ACME account registered)
```

If a cluster runs default-deny egress, also apply the egress policy and set
`<kube-apiserver-ip>` first:

```
kubectl apply -f deploy/k8s/cert-manager/networkpolicy-cert-manager-egress.yaml
```

## 4. Issue against STAGING first

`certificate-wildcard.yaml` ships with `issuerRef: letsencrypt-staging`.

```
kubectl apply -f deploy/k8s/traefik/certificate-wildcard.yaml
kubectl -n <traefik-namespace> get certificate wildcard-tls -w
```

Watch it go `Ready=True`. Staging roots are untrusted (browsers warn) -- that is
expected; staging only proves the whole RFC2136/TSIG/self-check path works with
generous rate limits.

## 5. Flip staging -> prod

Only after the **staging** cert is `Ready`:

```
kubectl -n <traefik-namespace> patch certificate wildcard-tls --type merge \
  -p '{"spec":{"issuerRef":{"name":"letsencrypt-prod","kind":"ClusterIssuer","group":"cert-manager.io"}}}'
# force a fresh prod cert by clearing the staging-issued Secret:
kubectl -n <traefik-namespace> delete secret wildcard-tls
kubectl -n <traefik-namespace> get certificate wildcard-tls -w
```

**Why staging-first:** LE **production** rate-limits failed validations
(5 / account / hostname / hour) and duplicate certs. A TSIG/self-check/firewall
misconfig fails repeatedly -- burn those failures against staging, not prod.
Confirm current limits at <https://letsencrypt.org/docs/rate-limits/>.

## 6. Point Traefik at the wildcard

Set Traefik's default TLS store to the `wildcard-tls` Secret (commented `TLSStore`
example in `certificate-wildcard.yaml`).

**Restart note:** if `wildcard-tls` did not exist when Traefik started, Traefik
serves its built-in self-signed cert. After issuance Traefik usually hot-reloads;
if the new cert is not picked up, restart/roll the Traefik pods so the default
store re-reads the Secret.

---

## Diagnostics -- a stuck or failing challenge

Walk the object chain top-down. cert-manager creates, per request:
`Certificate -> CertificateRequest -> Order -> Challenge`.

```
kubectl -n <traefik-namespace> describe certificate wildcard-tls
kubectl -n <traefik-namespace> get certificaterequest,order,challenge
kubectl -n <traefik-namespace> describe challenge <name>   # the money command
```

`describe challenge` shows the presented record, the DNS-01 self-check state, and
the ACME error. Read its `Status`/`Reason`/`Events` and branch:

### Challenge stays `pending`, self-check never passes -> split-horizon (BLOCKER-3)

Signal: challenge message like *"self check failed"* / *"DNS record ... not yet
propagated"* while the record **is** live on HE's public resolvers. Confirm from
your workstation against a public resolver:

```
dig +short TXT _acme-challenge.<domain> @1.1.1.1
```

- Public resolver **returns** the token but the challenge still fails
  -> cert-manager is querying the internal split-horizon view. Re-check step 1:
  `--dns01-recursive-nameservers-only` + `--dns01-recursive-nameservers` are on
  the controller. This is the single most common homelab failure.
- Public resolver returns **nothing** -> the record never reached HE. Look at the
  gateway logs / `astropath_provider_call_duration_seconds` (below), not cluster.

### Challenge errors immediately at the UPDATE -> TSIG failure

The gateway replies to the signed UPDATE with a coded error. Map it:

| Gateway reply | Meaning | Fix |
|---|---|---|
| **BADKEY** (17) | key name mismatch, or `tsigAlgorithm` wrong | `tsigKeyName` must byte-match the server key name **exactly** (trailing dot). `tsigAlgorithm: HMACSHA256` must be set -- the cert-manager default `HMACMD5` fails against the SHA-256 server (SPEC 14.1). |
| **BADSIG** (16) | MAC verify failed -- wrong secret, or double-base64 | The Secret value must be the **single**-base64 BIND string. Re-run the step-2 `base64 -d` check. A `.data` hand-encode double-base64s -> BADSIG. |
| **BADTIME** (18) | clock skew beyond fudge (300s) | NTP-sync the gateway host and cluster nodes (T-DEPLOY-08). Watch `astropath_tsig_badtime_total`; wire it to alerting. Skew > fudge = 100% failure. |
| **NOTAUTH**, no TSIG error | UPDATE arrived unsigned, or wrong port | cert-manager did not sign (missing `tsigSecretSecretRef`), or `<dns-port>` points at the wrong listener. |

The TSIG Secret is resolved in the **cluster-resource namespace** (default
`cert-manager`), not the Traefik namespace (SPEC 14.4). A Secret placed in the
workload namespace is silently not found -> the issuer never signs.

### No reply at all / timeout -> egress or firewall

- Default-deny cluster without the egress policy (step 3) -> silent timeout to
  `<gateway-ip>:<dns-port>` or to `1.1.1.1/8.8.8.8:53` or to ACME `:443`.
- Firewall opens only UDP -> a large signed UPDATE (>512 B) needs **TCP**
  fallback and hangs. Open **both** UDP and TCP (SPEC 14.7, T-DEPLOY-07).
- Source-IP mismatch: the gateway nftables allow-rule must cover the source the
  cluster actually egresses from -- node IPs (default Cilium masquerade) or pod
  CIDR (native routing). Cross-ref the Ansible nftables artifact.

### Record is live but the cert still lags -> downstream propagation, not astropath

HE / public-DNS propagation latency is outside astropath's control (SPEC 11.4,
LOW-4). Prove the **provider update** itself succeeded via the gateway's metrics
and logs -- this separates "astropath pushed the record" from "the world can see
it yet":

- `astropath_provider_call_duration_seconds{provider="hurricane"}` -- the push
  completed and how long it took.
- gateway log lines showing HE `good` / `nochg` -- HE accepted the value.
- `astropath_zone_last_success_timestamp{zone="<domain>"}` -- last good push.

If those show success, the record is pushed; remaining delay is public-DNS
propagation and LE's own validation query -- wait it out. cert-manager retries
the self-check with backoff.

---

## Wildcard coverage limit (SPEC 14.8)

`*.<domain>` covers exactly **one label**. It does **not** cover the apex
`<domain>`, and does **not** cover `a.b.<domain>`. v1 is wildcard-only (a single
`_acme-challenge.<domain>` challenge), matching HE's single-value dynamic record.
Apex+wildcard on one cert needs two concurrent TXT values -> a multi-value
provider (Route53) or HE account-login mode, out of scope for the M1 HE path. Do
not add `<domain>` to `dnsNames` on the HE path -- the second challenge has
nowhere to write.
