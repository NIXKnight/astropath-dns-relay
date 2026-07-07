// SPDX-License-Identifier: GPL-3.0-or-later
// AstropathDNSRelay — self-hosted ACME DNS-01 solver gateway.
// Copyright (C) 2026  Saad Ali. Licensed under the GNU GPL v3 or later; see the
// LICENSE file in the project root, or <https://www.gnu.org/licenses/>.

// TypeScript mirrors of the management-API schemas (src/astropath/api/schemas.py).
// Secrets are write-only server-side: read models never carry them, and the
// generated TSIG secret / API token appear exactly once in the *Created models.

export interface BackendRead {
  id: number
  name: string
  type: string
  created_at: string
  updated_at: string
}

export interface BackendCreate {
  name: string
  type: string
  config: Record<string, unknown>
}

export interface DomainRead {
  id: number
  zone: string
  backend_id: number
  record_name: string
  created_at: string
  has_secret: boolean
}

export interface DomainCreate {
  zone: string
  backend_id: number
  record_name: string
  he_dynamic_key?: string | null
}

export interface TsigKeyRead {
  id: number
  name: string
  algorithm: string
  created_at: string
}

export interface TsigKeyCreated extends TsigKeyRead {
  /** base64 BIND form — revealed exactly once (SPEC §9.2, §16). */
  secret: string
}

export interface ApiTokenRead {
  id: number
  name: string
  created_at: string
  last_used_at: string | null
}

export interface ApiTokenCreated extends ApiTokenRead {
  /** plaintext token — revealed exactly once (SPEC §9.2, §16). */
  token: string
}

export interface ChallengeEventRead {
  id: number
  ts: string
  zone: string
  record_name: string
  action: string
  provider: string
  result: string
  latency_ms: number
  tsig_key_id: number | null
  source: string
  error_detail: string | null
}

export interface ChallengeEventPage {
  items: ChallengeEventRead[]
  total: number
  limit: number
  offset: number
}

// --- Provider config schema (T-M4-03; served by GET /api/v1/backends/providers) ---

/** A minimal JSON Schema property node, enough to drive the credential form. */
export interface JsonSchemaProperty {
  title?: string
  type?: string
  format?: string
  default?: unknown
  writeOnly?: boolean
  enum?: string[]
  description?: string
  anyOf?: JsonSchemaProperty[]
}

export interface JsonSchema {
  title?: string
  description?: string
  type?: string
  properties?: Record<string, JsonSchemaProperty>
  required?: string[]
}

export interface ProviderSchema {
  type: string
  title: string
  supports_multivalue: boolean
  supports_delete: boolean
  config_schema: JsonSchema
}
