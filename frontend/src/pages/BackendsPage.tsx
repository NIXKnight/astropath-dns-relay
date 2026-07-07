// SPDX-License-Identifier: GPL-3.0-or-later
// astropath-dns-relay — self-hosted ACME DNS-01 solver gateway.
// Copyright (C) 2026  Saad Ali. Licensed under the GNU GPL v3 or later; see the
// LICENSE file in the project root, or <https://www.gnu.org/licenses/>.

import { useCallback, useState } from 'react'

import { api } from '../api/client.ts'
import type { BackendRead, ProviderSchema } from '../api/types.ts'
import { SchemaForm, schemaDefaults } from '../components/SchemaForm.tsx'
import { errorMessage, formatTimestamp } from '../lib/format.ts'
import { useResource } from '../lib/useResource.ts'

export function BackendsPage(): React.JSX.Element {
  const loadBackends = useCallback(() => api.get<BackendRead[]>('/backends'), [])
  const loadProviders = useCallback(
    () => api.get<ProviderSchema[]>('/backends/providers'),
    [],
  )
  const backends = useResource(loadBackends)
  const providers = useResource(loadProviders)

  const [name, setName] = useState('')
  const [type, setType] = useState('')
  const [config, setConfig] = useState<Record<string, unknown>>({})
  const [formError, setFormError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const selected = (providers.data ?? []).find((item) => item.type === type) ?? null

  // Picking a provider seeds the config with that schema's declared defaults;
  // the dynamic SchemaForm then renders one field per config property (T-M4-03).
  function selectType(nextType: string): void {
    setType(nextType)
    const provider = (providers.data ?? []).find((item) => item.type === nextType)
    setConfig(provider ? schemaDefaults(provider.config_schema) : {})
  }

  async function onCreate(event: React.FormEvent): Promise<void> {
    event.preventDefault()
    setFormError(null)
    setBusy(true)
    try {
      await api.post<BackendRead>('/backends', { name, type, config })
      setName('')
      setType('')
      setConfig({})
      backends.reload()
    } catch (err) {
      setFormError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  async function onDelete(backend: BackendRead): Promise<void> {
    if (!window.confirm(`Delete backend "${backend.name}"?`)) {
      return
    }
    try {
      await api.del(`/backends/${backend.id}`)
      backends.reload()
    } catch (err) {
      window.alert(errorMessage(err))
    }
  }

  return (
    <section className="page">
      <header className="page-head">
        <h1>Backends</h1>
        <p className="muted">
          Provider backends hold shared config (encrypted at rest, write-only). The
          credential form is generated from each provider&apos;s config schema.
        </p>
      </header>

      <form className="card form-grid" onSubmit={(event) => void onCreate(event)}>
        <h2>Add backend</h2>
        {formError && (
          <p className="notice notice-error field-wide" role="alert">
            {formError}
          </p>
        )}
        {providers.error && (
          <p className="notice notice-error field-wide">{providers.error}</p>
        )}
        <label className="field">
          <span>Name</span>
          <input
            value={name}
            onChange={(event) => setName(event.target.value)}
            required
          />
        </label>
        <label className="field">
          <span>Type</span>
          <select
            value={type}
            onChange={(event) => selectType(event.target.value)}
            required
          >
            <option value="">Select provider…</option>
            {(providers.data ?? []).map((provider) => (
              <option key={provider.type} value={provider.type}>
                {provider.type}
              </option>
            ))}
          </select>
        </label>

        {selected && (
          <>
            <div className="field-wide divider">
              Configuration — <code>{selected.title}</code>
            </div>
            <SchemaForm
              schema={selected.config_schema}
              values={config}
              onChange={(field, value) =>
                setConfig((current) => ({ ...current, [field]: value }))
              }
            />
          </>
        )}

        <div className="form-actions">
          <button type="submit" className="primary" disabled={busy || !type}>
            {busy ? 'Creating…' : 'Create backend'}
          </button>
        </div>
      </form>

      <div className="card">
        <h2>Configured backends</h2>
        {backends.error && <p className="notice notice-error">{backends.error}</p>}
        {backends.loading && !backends.data ? (
          <p className="muted">Loading…</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Name</th>
                <th>Type</th>
                <th>Created</th>
                <th aria-label="Actions" />
              </tr>
            </thead>
            <tbody>
              {(backends.data ?? []).map((backend) => (
                <tr key={backend.id}>
                  <td>{backend.id}</td>
                  <td>{backend.name}</td>
                  <td>
                    <code>{backend.type}</code>
                  </td>
                  <td>{formatTimestamp(backend.created_at)}</td>
                  <td className="row-actions">
                    <button
                      type="button"
                      className="danger"
                      onClick={() => void onDelete(backend)}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
              {(backends.data ?? []).length === 0 && (
                <tr>
                  <td colSpan={5} className="muted">
                    No backends yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>
    </section>
  )
}
