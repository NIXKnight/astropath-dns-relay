// SPDX-License-Identifier: GPL-3.0-or-later
// AstropathDNSRelay — self-hosted ACME DNS-01 solver gateway.
// Copyright (C) 2026  Saad Ali. Licensed under the GNU GPL v3 or later; see the
// LICENSE file in the project root, or <https://www.gnu.org/licenses/>.

import { useCallback, useState } from 'react'

import { api } from '../api/client.ts'
import type { BackendRead } from '../api/types.ts'
import { errorMessage, formatTimestamp } from '../lib/format.ts'
import { useResource } from '../lib/useResource.ts'

export function BackendsPage(): React.JSX.Element {
  const load = useCallback(() => api.get<BackendRead[]>('/backends'), [])
  const { data, error, loading, reload } = useResource(load)

  const [name, setName] = useState('')
  const [type, setType] = useState('')
  const [configText, setConfigText] = useState('{}')
  const [formError, setFormError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function onCreate(event: React.FormEvent): Promise<void> {
    event.preventDefault()
    setFormError(null)

    let config: Record<string, unknown> = {}
    if (configText.trim()) {
      let parsed: unknown
      try {
        parsed = JSON.parse(configText)
      } catch {
        setFormError('Config must be valid JSON.')
        return
      }
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        setFormError('Config must be a JSON object.')
        return
      }
      config = parsed as Record<string, unknown>
    }

    setBusy(true)
    try {
      await api.post<BackendRead>('/backends', { name, type, config })
      setName('')
      setType('')
      setConfigText('{}')
      reload()
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
      reload()
    } catch (err) {
      window.alert(errorMessage(err))
    }
  }

  return (
    <section className="page">
      <header className="page-head">
        <h1>Backends</h1>
        <p className="muted">
          Provider backends hold shared config (encrypted at rest, write-only).
        </p>
      </header>

      <form className="card form-grid" onSubmit={(event) => void onCreate(event)}>
        <h2>Add backend</h2>
        {formError && (
          <p className="notice notice-error" role="alert">
            {formError}
          </p>
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
          <input
            value={type}
            onChange={(event) => setType(event.target.value)}
            placeholder="hurricane"
            required
          />
        </label>
        <label className="field field-wide">
          <span>Config (JSON)</span>
          <textarea
            className="mono"
            rows={4}
            value={configText}
            onChange={(event) => setConfigText(event.target.value)}
          />
        </label>
        <div className="form-actions">
          <button type="submit" className="primary" disabled={busy}>
            {busy ? 'Creating…' : 'Create backend'}
          </button>
        </div>
      </form>

      <div className="card">
        <h2>Configured backends</h2>
        {error && <p className="notice notice-error">{error}</p>}
        {loading && !data ? (
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
              {(data ?? []).map((backend) => (
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
              {(data ?? []).length === 0 && (
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
