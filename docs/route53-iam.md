<!--
SPDX-License-Identifier: GPL-3.0-or-later
AstropathDNSRelay — Copyright (C) 2026 Saad Ali
-->

# Route 53 backend — least-privilege IAM policy (T-M5-03, SPEC §5.8)

`route53-iam-policy.json` is the least-privilege policy for the AWS credentials
AstropathDNSRelay uses for a Route 53 backend. The access key + secret are stored
**encrypted** in `Backend.config_encrypted` (never in the environment / instance
profile — SPEC §5.8); this policy is attached to the IAM user or role that owns
those credentials.

All identifiers in the JSON are **placeholders**. Before applying:

- replace `ZONEID_PLACEHOLDER` with the target hosted-zone id
  (e.g. `Z0123456789ABCDEFGHIJ`);
- replace `_acme-challenge.example.com` with the challenge name(s) for each
  managed zone (the normalized form: lower-case, **no** trailing dot).

Never commit a real account id or hosted-zone id.

## What it grants

| Statement | Action(s) | Resource | Scope |
|---|---|---|---|
| `AstropathAcmeChallengeWrite` | `route53:ChangeResourceRecordSets` | the one hosted zone (never `*`) | conditioned to `_acme-challenge` names, `TXT` type, `UPSERT`/`DELETE` actions |
| `AstropathReadRecordsAndZone` | `route53:ListResourceRecordSets`, `route53:GetHostedZone` | the one hosted zone | zone-wide (see caveat) |
| `AstropathGetChange` | `route53:GetChange` | `change/*` | change-status polling (optional INSYNC, T-M5-04) |

- `ChangeResourceRecordSets` is the only **write**; it is pinned to the single
  hosted-zone ARN and further constrained by the condition keys so a compromised
  credential cannot touch non-`_acme-challenge` records, non-TXT types, or
  create/other actions. This mirrors the data-plane write-surface allowlist
  (BLOCKER-2) at the cloud-IAM layer.
- `ListResourceRecordSets` backs `cleanup()`'s read-before-delete (Route 53
  requires the exact record body to delete — SPEC §5.8). `GetHostedZone` backs
  `validate()`. `GetChange` backs the optional `INSYNC` propagation poll.

## `[ASSERT]` — build-time verification (SPEC §18.1)

Prove the following against the **AWS Service Authorization Reference**
(`Actions, resources, and condition keys for Amazon Route 53`) before relying on
this policy in production — they are version/vendor-sensitive and not provable
from the pinned libraries:

1. **Condition-key spelling.** Exact keys:
   `route53:ChangeResourceRecordSetsNormalizedRecordNames`,
   `route53:ChangeResourceRecordSetsRecordTypes`,
   `route53:ChangeResourceRecordSetsActions`.
2. **Operator.** These keys are **multivalued**, so `ForAllValues:StringEquals`
   is used here to require that *every* value in a request is allow-listed. Verify
   the operator; also note the IAM gotcha that `ForAllValues` evaluates **true**
   for a request that carries **no** values for the key — the write is still
   bounded by the resource ARN and by the value list, but do not rely on the
   condition alone to deny an empty request.
3. **Normalized record-name form.** Confirm the value form Route 53 matches
   against (lower-case, no trailing dot, octal-escaped specials).
4. **`GetChange` resource.** Confirm `GetChange` scopes to `arn:aws:route53:::change/*`
   (it does not support a per-change resource restriction).

## Zone-wide read caveat (state in the security model — SPEC §5.8, HIGH-9)

`route53:ListResourceRecordSets` **cannot be name-scoped**: Route 53 exposes no
condition key that restricts a *list* to a single record name. A policy whose
**write** is narrowed to `_acme-challenge`/TXT therefore still permits **zone-wide
reads** of every record in the hosted zone. This is inherent to Route 53 IAM, not
a defect in AstropathDNSRelay. If a hosted zone holds records more sensitive than
its public DNS already reveals, isolate the ACME challenge names in a **dedicated
hosted zone / delegated subzone** so the read surface is limited to challenge
records only.
