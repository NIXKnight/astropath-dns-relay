// SPDX-License-Identifier: GPL-3.0-or-later
// AstropathDNSRelay — self-hosted ACME DNS-01 solver gateway.
// Copyright (C) 2026  Saad Ali. Licensed under the GNU GPL v3 or later; see the
// LICENSE file in the project root, or <https://www.gnu.org/licenses/>.

// Mirrors ONE_TIME_SECRET_NOTICE in src/astropath/api/schemas.py verbatim (it is
// the OpenAPI response_description of every secret-minting endpoint). Rendered in
// the reveal modal so the operator sees the one-time / revoke+recreate policy at
// the moment the value is shown (SPEC §9.2, §16, LOW-1).
export const ONE_TIME_SECRET_NOTICE =
  'The generated secret is shown exactly once, in this response only. It is not ' +
  'stored in recoverable form and cannot be retrieved again. If it is lost, revoke ' +
  'this credential and create a new one — the value is never redisplayed.'
