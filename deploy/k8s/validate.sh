#!/usr/bin/env bash
# astropath-dns-relay -- deploy manifest validation.
# Task: T-TEST-20 (cert-manager / k8s deploy artifact validation). SPEC 14.
#
# Two independent gates:
#   1. STRUCTURAL asserts (always run; no docker needed) -- encode the
#      load-bearing traps from SPEC 14 so a manifest edit cannot silently
#      regress them (HMACMD5 default, double-base64 Secret, wrong namespace,
#      missing UDP/TCP, split-horizon resolver flags, prod-vs-staging server).
#   2. SCHEMA validation via kubeconform in docker (skipped cleanly if docker is
#      absent or the daemon is unreachable) -- validates every manifest against
#      the upstream Kubernetes + cert-manager CRD JSON schemas.
#
# The manifests carry angle-bracket placeholders (<gateway-ip>, <domain>, ...);
# kubeconform validates STRUCTURE/TYPES, not value semantics, so placeholders in
# string fields pass. Secrets are never present -- only the <TSIG-SECRET-BASE64>
# placeholder.
#
# Usage:  ./validate.sh
# Exit:   0 = all gates passed (or schema gate cleanly skipped); 1 = a failure.
#
# Overridable:
#   KUBECONFORM_IMAGE  (default ghcr.io/yannh/kubeconform:v0.6.7)
#   CRD_SCHEMA_BASE     (default datreeio/CRDs-catalog main)
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
KUBECONFORM_IMAGE="${KUBECONFORM_IMAGE:-ghcr.io/yannh/kubeconform:v0.6.7}"
CRD_SCHEMA_BASE="${CRD_SCHEMA_BASE:-https://raw.githubusercontent.com/datreeio/CRDs-catalog/main}"

# Kubernetes manifests (validated by kubeconform). Paths are relative to
# SCRIPT_DIR so the docker mount and the structural greps agree.
MANIFESTS=(
  "cert-manager/clusterissuer-letsencrypt-staging.yaml"
  "cert-manager/clusterissuer-letsencrypt-prod.yaml"
  "cert-manager/tsig-secret.example.yaml"
  "cert-manager/networkpolicy-cert-manager-egress.yaml"
  "traefik/certificate-wildcard.yaml"
)
# Helm values fragment -- NOT a k8s resource, excluded from kubeconform.
HELM_VALUES="cert-manager/helm-values.cert-manager.yaml"

fail_count=0
pass()  { printf '  PASS  %s\n' "$1"; }
fail()  { printf '  FAIL  %s\n' "$1"; fail_count=$((fail_count + 1)); }

# assert_grep FILE ERE DESC  -- pattern MUST be present.
assert_grep() {
  if grep -Eq -- "$2" "$SCRIPT_DIR/$1"; then pass "$3"; else
    fail "$3 -- expected /$2/ in $1"; fi
}
# assert_absent FILE ERE DESC -- pattern MUST NOT be present.
assert_absent() {
  if grep -Eq -- "$2" "$SCRIPT_DIR/$1"; then
    fail "$3 -- unexpected /$2/ in $1"; else pass "$3"; fi
}
# assert_absent_code FILE ERE DESC -- pattern MUST NOT appear on a non-comment
# line (whole-line `#` comments are ignored, so educational comments may name the
# forbidden token while the guard still catches it as an active field value).
assert_absent_code() {
  if grep -Ev '^[[:space:]]*#' "$SCRIPT_DIR/$1" | grep -Eq -- "$2"; then
    fail "$3 -- unexpected /$2/ on a non-comment line of $1"; else pass "$3"; fi
}

echo "== structural asserts (SPEC 14 trap-guards) =="

# Every manifest file must exist.
for m in "${MANIFESTS[@]}" "$HELM_VALUES"; do
  if [ -f "$SCRIPT_DIR/$m" ]; then pass "present: $m"; else fail "missing: $m"; fi
done

# T-DEPLOY-01 / T-DEPLOY-04 -- tsigAlgorithm pinned dashless; HMACMD5 never used.
for issuer in \
  "cert-manager/clusterissuer-letsencrypt-staging.yaml" \
  "cert-manager/clusterissuer-letsencrypt-prod.yaml"; do
  assert_grep        "$issuer" 'tsigAlgorithm:[[:space:]]*HMACSHA256' "$issuer pins tsigAlgorithm HMACSHA256"
  assert_absent_code "$issuer" 'HMACMD5'                              "$issuer avoids HMACMD5 default (active field)"
  assert_grep   "$issuer" 'name:[[:space:]]*tsig-secret'         "$issuer references Secret name tsig-secret"
  assert_grep   "$issuer" 'key:[[:space:]]*tsig-secret-key'      "$issuer references Secret key tsig-secret-key"
  assert_grep   "$issuer" 'nameserver:[[:space:]]*"<gateway-ip>:<dns-port>"' "$issuer uses gateway IP-literal placeholder"
done

# T-DEPLOY-04 -- staging vs prod ACME servers are correct and not swapped.
assert_grep   "cert-manager/clusterissuer-letsencrypt-staging.yaml" 'acme-staging-v02\.api\.letsencrypt\.org' "staging issuer uses acme-staging-v02"
assert_grep   "cert-manager/clusterissuer-letsencrypt-prod.yaml"    '//acme-v02\.api\.letsencrypt\.org'       "prod issuer uses acme-v02"
assert_absent "cert-manager/clusterissuer-letsencrypt-prod.yaml"    'acme-staging-v02'                        "prod issuer is not accidentally staging"

# T-DEPLOY-03 -- TSIG Secret: stringData (never .data), cert-manager ns, placeholder only.
assert_grep   "cert-manager/tsig-secret.example.yaml" 'stringData:'                         "TSIG Secret uses stringData"
assert_absent "cert-manager/tsig-secret.example.yaml" '^[[:space:]]*data:'                  "TSIG Secret avoids hand-encoded .data (double-base64 trap)"
assert_grep   "cert-manager/tsig-secret.example.yaml" 'namespace:[[:space:]]*cert-manager'  "TSIG Secret lives in cert-manager ns"
assert_grep   "cert-manager/tsig-secret.example.yaml" 'tsig-secret-key:[[:space:]]*<TSIG-SECRET-BASE64>' "TSIG Secret value is the placeholder (no real secret)"

# T-DEPLOY-06 -- wildcard Certificate: workload ns (not cert-manager), wildcard-only.
assert_grep   "traefik/certificate-wildcard.yaml" '"\*\.<domain>"'                     "Certificate requests *.<domain>"
assert_grep   "traefik/certificate-wildcard.yaml" 'namespace:[[:space:]]*<traefik-namespace>' "Certificate lives in the Traefik/workload ns"
assert_absent "traefik/certificate-wildcard.yaml" '^[[:space:]]*namespace:[[:space:]]*cert-manager' "Certificate is NOT in the cert-manager ns"
assert_grep   "traefik/certificate-wildcard.yaml" 'kind:[[:space:]]*ClusterIssuer'      "Certificate issuerRef is a ClusterIssuer"

# T-DEPLOY-05 -- egress: gateway UDP+TCP, both public resolvers, ACME 443.
assert_grep   "cert-manager/networkpolicy-cert-manager-egress.yaml" 'protocol:[[:space:]]*UDP'  "NetworkPolicy opens UDP"
assert_grep   "cert-manager/networkpolicy-cert-manager-egress.yaml" 'protocol:[[:space:]]*TCP'  "NetworkPolicy opens TCP"
assert_grep   "cert-manager/networkpolicy-cert-manager-egress.yaml" 'port:[[:space:]]*<dns-port>' "NetworkPolicy targets the gateway <dns-port>"
assert_grep   "cert-manager/networkpolicy-cert-manager-egress.yaml" '1\.1\.1\.1/32'            "NetworkPolicy allows resolver 1.1.1.1"
assert_grep   "cert-manager/networkpolicy-cert-manager-egress.yaml" '8\.8\.8\.8/32'            "NetworkPolicy allows resolver 8.8.8.8"
assert_grep   "cert-manager/networkpolicy-cert-manager-egress.yaml" 'port:[[:space:]]*443'     "NetworkPolicy allows ACME 443"

# T-DEPLOY-02 -- split-horizon self-check flags (BLOCKER-3).
assert_grep   "$HELM_VALUES" 'extraArgs:'                                          "Helm values use extraArgs"
assert_grep   "$HELM_VALUES" '--dns01-recursive-nameservers-only'                  "Helm values set recursive-nameservers-only"
assert_grep   "$HELM_VALUES" '--dns01-recursive-nameservers=1\.1\.1\.1:53,8\.8\.8\.8:53' "Helm values pin public resolvers"

echo
echo "== schema validation (kubeconform via docker) =="
if ! command -v docker >/dev/null 2>&1; then
  echo "  SKIP  docker not found -- structural asserts stand; re-run with docker for schema validation"
elif ! docker info >/dev/null 2>&1; then
  echo "  SKIP  docker daemon unreachable -- structural asserts stand"
else
  set +e
  docker run --rm -v "$SCRIPT_DIR":/work -w /work "$KUBECONFORM_IMAGE" \
    -strict -summary -verbose \
    -schema-location default \
    -schema-location "$CRD_SCHEMA_BASE/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json" \
    -ignore-missing-schemas \
    "${MANIFESTS[@]}"
  kc_rc=$?
  set -e
  if [ "$kc_rc" -ne 0 ]; then
    fail "kubeconform reported schema violations (exit $kc_rc)"
  else
    pass "kubeconform: all manifests structurally valid"
  fi
fi

echo
if [ "$fail_count" -eq 0 ]; then
  echo "RESULT: PASS (0 failures)"
  exit 0
fi
echo "RESULT: FAIL ($fail_count failure(s))"
exit 1
