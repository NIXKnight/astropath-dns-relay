# Hurricane Electric propagation diagnostics (runbook)

> Task T-M6-08 · SPEC §5.7, §11.1, §11.4, §16 · remediation LOW-4

This runbook answers one operational question: **when a wildcard certificate is
stuck, is it AstropathDNSRelay's fault or not?** The gateway is a *write-path only*
service — it pushes the `_acme-challenge` TXT value to the provider and stops
there. Everything after the push (public DNS propagation, cert-manager's
self-check, Let's Encrypt validation) queries the provider's real public
nameservers, which AstropathDNSRelay never controls.

So there are two distinct failure classes, and they are diagnosed differently:

| Class | Meaning | Owner |
|---|---|---|
| **Provider push failed** | The HE API rejected or errored the update | AstropathDNSRelay surfaces it |
| **Public visibility lagging** | HE accepted the write but public resolvers do not serve it yet | HE / public DNS — outside the gateway |

## 1. Did the provider push succeed?

The push is what AstropathDNSRelay can prove. Every challenge produces one
outcome, visible in both metrics and logs.

### Metrics (`/metrics`, LAN-only)

- `astropath_challenges_total{provider="hurricane",action,result}` — the counter
  increments with `result="ok"` on a successful push, `result="error"` on a
  provider rejection. A rising `result="error"` is a real gateway-side problem.
- `astropath_provider_call_duration_seconds{provider="hurricane"}` — the latency
  histogram of the HE API call itself. This measures *only* the outbound HTTP
  round-trip to `dyn.dns.he.net`, not any downstream propagation.
- `astropath_zone_last_success_timestamp{zone}` — the Unix time of the last
  successful push per zone. `time() - <value>` is "seconds since this zone last
  had a challenge accepted by the provider". A stale value during a renewal
  window points at the gateway/provider; a fresh value points downstream.

### Logs (stdout, structured)

Each challenge emits one outcome line from `astropath.dispatcher`:

```
challenge present ok zone=example.com. provider=hurricane latency_ms=142 source=10.0.0.5
```

- `ok` ⇔ HE returned `good` or `nochg` (SPEC §5.7) — the value is set at HE.
- `error` ⇔ HE returned a hard error (`badauth`, `nohost`, `!yours`, `notfqdn`,
  `abuse`) or the HTTP call failed. The provider error string is in the
  `ChallengeEvent` audit row's `error_detail` (never a secret).

The HE per-record dynamic key is **never** logged (redacted; SPEC §5.7, §11.4).

### Audit trail

`GET /api/v1/events` returns the append-only `ChallengeEvent` rows: `zone`,
`action`, `provider`, `result`, `latency_ms`, `source`, and `error_detail`. One
row per challenge. This is the durable record that a push happened and how it
turned out.

### Correlation ids

Every log record for one inbound UPDATE shares a `dns-<reqid>-<rand>` correlation
id (the `[...]` field in each line; SPEC §11.4). Grep a single challenge's whole
lifecycle — parse → dispatch → HE call → audit — with that one id.

## 2. Push succeeded but the certificate is still pending

If the outcome is `ok` (and the audit row confirms it) but cert-manager's
challenge stays `pending`, the gateway has done its job. The remaining latency is
**HE + public-DNS propagation**, which AstropathDNSRelay cannot observe or
accelerate. Expected behavior:

- HE applies a dynamic-record update quickly at its own authoritative servers,
  but public recursive resolvers (and cert-manager's self-check resolvers) only
  see it after their cache TTL and HE's internal propagation settle. This is
  normally seconds-to-low-minutes but is not bounded by the gateway.
- cert-manager's self-check **must** be pointed at public recursive resolvers
  (`--dns01-recursive-nameservers-only`, BLOCKER-3 / SPEC §14.3). In a
  split-horizon homelab a self-check against an internal view of the zone will
  never see HE's public TXT, so the challenge hangs even though the push
  succeeded. Verify those controller flags first.

Confirm public visibility directly, bypassing any split-horizon view:

```
dig +short TXT _acme-challenge.example.com @1.1.1.1
dig +short TXT _acme-challenge.example.com @8.8.8.8
```

- Value present at public resolvers → propagation is done; look at cert-manager
  self-check config / LE, not the gateway.
- Value absent while the gateway logged `ok` → HE-side propagation lag; wait and
  re-check. Persisting for long implies an HE dashboard prerequisite issue
  (record not pre-created / not flagged dynamic / wrong dynamic key — SPEC §5.7),
  which would usually have surfaced earlier as `result="error"` `badauth`/`nohost`.

## 3. Quick triage checklist

1. `astropath_challenges_total{result="error"}` rising, or outcome log shows
   `error`? → gateway/provider issue. Read `error_detail` (audit row): `badauth`
   → wrong/expired HE dynamic key; `nohost` → record not pre-created/flagged
   dynamic at HE. Fix the HE dashboard prerequisite or the stored key.
2. Outcome `ok` but `dig @1.1.1.1` shows no TXT → propagation lag; wait.
3. `dig @1.1.1.1` shows the TXT but the challenge still pending → cert-manager
   self-check resolvers / Let's Encrypt, not the gateway (SPEC §14.3).
4. Clock skew? A `BADTIME` spike (`astropath_tsig_badtime_total`) means TSIG
   fails before any push — fix host NTP (SPEC §14, DEPLOY T-DEPLOY-08).
