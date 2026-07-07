// SPDX-License-Identifier: GPL-3.0-or-later
// AstropathDNSRelay — self-hosted ACME DNS-01 solver gateway.
// Copyright (C) 2026  Saad Ali. Licensed under the GNU GPL v3 or later; see the
// LICENSE file in the project root, or <https://www.gnu.org/licenses/>.

import type { JsonSchema, JsonSchemaProperty } from '../api/types.ts'

// Renders form fields from a provider's config JSON Schema (served by
// GET /api/v1/backends/providers). A new provider gets a correct credential form
// with no bespoke UI code (SPEC §5.2, T-M4-03). Secret fields (SecretStr →
// writeOnly + format:password) render as write-only password inputs.

/** The primitive field type, resolving ``anyOf`` (optional/nullable) unions. */
function fieldType(prop: JsonSchemaProperty): string {
  if (prop.type) {
    return prop.type
  }
  const nonNull = prop.anyOf?.find((sub) => sub.type && sub.type !== 'null')
  return nonNull?.type ?? 'string'
}

function isNullable(prop: JsonSchemaProperty): boolean {
  return Boolean(prop.anyOf?.some((sub) => sub.type === 'null'))
}

function isSecret(prop: JsonSchemaProperty): boolean {
  return prop.writeOnly === true || prop.format === 'password'
}

/** Seed a config object from the schema's declared defaults (secrets stay unset). */
export function schemaDefaults(schema: JsonSchema): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const [name, prop] of Object.entries(schema.properties ?? {})) {
    if (prop.default !== undefined) {
      out[name] = prop.default
    }
  }
  return out
}

function asText(value: unknown): string {
  return value === undefined || value === null ? '' : String(value)
}

interface SchemaFormProps {
  schema: JsonSchema
  values: Record<string, unknown>
  onChange: (name: string, value: unknown) => void
}

export function SchemaForm({
  schema,
  values,
  onChange,
}: SchemaFormProps): React.JSX.Element {
  const properties = Object.entries(schema.properties ?? {})
  const required = new Set(schema.required ?? [])

  if (properties.length === 0) {
    return <p className="muted">This provider needs no configuration.</p>
  }

  return (
    <>
      {properties.map(([name, prop]) => {
        const type = fieldType(prop)
        const label = prop.title ?? name
        const isRequired = required.has(name)
        const raw = values[name]

        if (type === 'boolean') {
          return (
            <label className="field field-check" key={name}>
              <input
                type="checkbox"
                checked={raw === true}
                onChange={(event) => onChange(name, event.target.checked)}
              />
              <span>{label}</span>
            </label>
          )
        }

        if (prop.enum && prop.enum.length > 0) {
          return (
            <label className="field" key={name}>
              <span>
                {label}
                {isRequired && ' *'}
              </span>
              <select
                value={asText(raw)}
                required={isRequired}
                onChange={(event) => onChange(name, event.target.value)}
              >
                <option value="">Select…</option>
                {prop.enum.map((option) => (
                  <option key={option} value={option}>
                    {option}
                  </option>
                ))}
              </select>
            </label>
          )
        }

        const secret = isSecret(prop)
        const numeric = type === 'integer' || type === 'number'
        const inputType = secret ? 'password' : numeric ? 'number' : 'text'

        return (
          <label className="field" key={name}>
            <span>
              {label}
              {isRequired && ' *'}
              {secret && ' (write-only)'}
            </span>
            <input
              type={inputType}
              autoComplete={secret ? 'new-password' : 'off'}
              value={asText(raw)}
              required={isRequired}
              onChange={(event) => {
                const next = event.target.value
                if (numeric) {
                  onChange(name, next === '' ? null : Number(next))
                } else if (next === '' && isNullable(prop)) {
                  onChange(name, null)
                } else {
                  onChange(name, next)
                }
              }}
            />
            {prop.description && <small className="muted">{prop.description}</small>}
          </label>
        )
      })}
    </>
  )
}
