// SPDX-License-Identifier: GPL-3.0-or-later
// AstropathDNSRelay — self-hosted ACME DNS-01 solver gateway.
// Copyright (C) 2026  Saad Ali. Licensed under the GNU GPL v3 or later; see the
// LICENSE file in the project root, or <https://www.gnu.org/licenses/>.

import { useCallback, useState } from 'react'

import { api } from '../api/client.ts'
import type { BackendRead, DomainRead } from '../api/types.ts'
import { errorMessage, formatTimestamp } from '../lib/format.ts'
import { useResource } from '../lib/useResource.ts'

export function DomainsPage(): React.JSX.Element {
  const loadDomains = useCallback(() => api.get<DomainRead[]>('/domains'), [])
  const loadBackends = useCallback(() => api.get<BackendRead[]>('/backends'), [])
  const domains = useResource(loadDomains)
  const backends = useResource(loadBackends)

  const [zone, setZone] = useState('')
  const [backendId, setBackendId] = useState('')
  const [recordName, setRecordName] = useState('')
  const [heKey, setHeKey] = useState('')
  const [formError, setFormError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  function backendName(id: number): string {
    const match = (backends.data ?? []).find((backend) => backend.id === id)
    return match ? match.name : `#${id}`
  }

  async function onCreate(event: React.FormEvent): Promise<void> {
    event.preventDefault()
    setFormError(null)
    if (!backendId) {
      setFormError('Select a backend.')
      return
    }
    setBusy(true)
    try {
      await api.post<DomainRead>('/domains', {
        zone,
        backend_id: Number(backendId),
        record_name: recordName,
        he_dynamic_key: heKey.trim() ? heKey : null,
      })
      setZone('')
      setBackendId('')
      setRecordName('')
      setHeKey('')
      domains.reload()
    } catch (err) {
      setFormError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  async function onDelete(domain: DomainRead): Promise<void> {
    if (!window.confirm(`Unmap zone "${domain.zone}"?`)) {
      return
    }
    try {
      await api.del(`/domains/${domain.id}`)
      domains.reload()
    } catch (err) {
      window.alert(errorMessage(err))
    }
  }

  return (
    <section className="page">
      <header className="page-head">
        <h1>Domains</h1>
        <p className="muted">
          Zone → backend routing. The HE per-record dynamic key is write-only and
          domain-scoped; it is never returned on read.
        </p>
      </header>

      <form className="card form-grid" onSubmit={(event) => void onCreate(event)}>
        <h2>Map a zone</h2>
        {formError && (
          <p className="notice notice-error" role="alert">
            {formError}
          </p>
        )}
        <label className="field">
          <span>Zone</span>
          <input
            value={zone}
            onChange={(event) => setZone(event.target.value)}
            placeholder="example.com."
            required
          />
        </label>
        <label className="field">
          <span>Backend</span>
          <select
            value={backendId}
            onChange={(event) => setBackendId(event.target.value)}
            required
          >
            <option value="">Select…</option>
            {(backends.data ?? []).map((backend) => (
              <option key={backend.id} value={backend.id}>
                {backend.name} ({backend.type})
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>Record name</span>
          <input
            value={recordName}
            onChange={(event) => setRecordName(event.target.value)}
            placeholder="_acme-challenge.example.com."
            required
          />
        </label>
        <label className="field">
          <span>HE dynamic key (optional, write-only)</span>
          <input
            type="password"
            autoComplete="off"
            value={heKey}
            onChange={(event) => setHeKey(event.target.value)}
          />
        </label>
        <div className="form-actions">
          <button type="submit" className="primary" disabled={busy}>
            {busy ? 'Mapping…' : 'Map zone'}
          </button>
        </div>
      </form>

      <div className="card">
        <h2>Mapped zones</h2>
        {domains.error && <p className="notice notice-error">{domains.error}</p>}
        {domains.loading && !domains.data ? (
          <p className="muted">Loading…</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Zone</th>
                <th>Backend</th>
                <th>Record name</th>
                <th>HE key</th>
                <th>Created</th>
                <th aria-label="Actions" />
              </tr>
            </thead>
            <tbody>
              {(domains.data ?? []).map((domain) => (
                <tr key={domain.id}>
                  <td>
                    <code>{domain.zone}</code>
                  </td>
                  <td>{backendName(domain.backend_id)}</td>
                  <td>
                    <code>{domain.record_name}</code>
                  </td>
                  <td>{domain.has_secret ? 'set' : '—'}</td>
                  <td>{formatTimestamp(domain.created_at)}</td>
                  <td className="row-actions">
                    <button
                      type="button"
                      className="danger"
                      onClick={() => void onDelete(domain)}
                    >
                      Unmap
                    </button>
                  </td>
                </tr>
              ))}
              {(domains.data ?? []).length === 0 && (
                <tr>
                  <td colSpan={6} className="muted">
                    No zones mapped yet.
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
