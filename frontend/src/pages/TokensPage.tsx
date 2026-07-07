// SPDX-License-Identifier: GPL-3.0-or-later
// AstropathDNSRelay — self-hosted ACME DNS-01 solver gateway.
// Copyright (C) 2026  Saad Ali. Licensed under the GNU GPL v3 or later; see the
// LICENSE file in the project root, or <https://www.gnu.org/licenses/>.

import { useCallback, useState } from 'react'

import { api } from '../api/client.ts'
import type { ApiTokenCreated, ApiTokenRead } from '../api/types.ts'
import { OneTimeSecretModal } from '../components/OneTimeSecretModal.tsx'
import { errorMessage, formatTimestamp } from '../lib/format.ts'
import { useResource } from '../lib/useResource.ts'

export function TokensPage(): React.JSX.Element {
  const load = useCallback(() => api.get<ApiTokenRead[]>('/tokens'), [])
  const { data, error, loading, reload } = useResource(load)

  const [name, setName] = useState('')
  const [formError, setFormError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [revealed, setRevealed] = useState<string | null>(null)

  async function onCreate(event: React.FormEvent): Promise<void> {
    event.preventDefault()
    setFormError(null)
    setBusy(true)
    try {
      const created = await api.post<ApiTokenCreated>('/tokens', { name })
      setRevealed(created.token) // shown once, held only in memory
      setName('')
      reload()
    } catch (err) {
      setFormError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  async function onRevoke(token: ApiTokenRead): Promise<void> {
    if (!window.confirm(`Revoke API token "${token.name}"?`)) {
      return
    }
    try {
      await api.del(`/tokens/${token.id}`)
      reload()
    } catch (err) {
      window.alert(errorMessage(err))
    }
  }

  return (
    <section className="page">
      <header className="page-head">
        <h1>API Tokens</h1>
        <p className="muted">
          Tokens authenticate scripts via the <code>X-API-Key</code> header. Only a
          hash is stored; the value is shown once at creation.
        </p>
      </header>

      <form className="card form-grid" onSubmit={(event) => void onCreate(event)}>
        <h2>Mint a token</h2>
        {formError && (
          <p className="notice notice-error" role="alert">
            {formError}
          </p>
        )}
        <label className="field">
          <span>Label</span>
          <input
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder="ci-pipeline"
            required
          />
        </label>
        <div className="form-actions">
          <button type="submit" className="primary" disabled={busy}>
            {busy ? 'Minting…' : 'Mint token'}
          </button>
        </div>
      </form>

      <div className="card">
        <h2>Tokens</h2>
        {error && <p className="notice notice-error">{error}</p>}
        {loading && !data ? (
          <p className="muted">Loading…</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Label</th>
                <th>Created</th>
                <th>Last used</th>
                <th aria-label="Actions" />
              </tr>
            </thead>
            <tbody>
              {(data ?? []).map((token) => (
                <tr key={token.id}>
                  <td>{token.id}</td>
                  <td>{token.name}</td>
                  <td>{formatTimestamp(token.created_at)}</td>
                  <td>{formatTimestamp(token.last_used_at)}</td>
                  <td className="row-actions">
                    <button
                      type="button"
                      className="danger"
                      onClick={() => void onRevoke(token)}
                    >
                      Revoke
                    </button>
                  </td>
                </tr>
              ))}
              {(data ?? []).length === 0 && (
                <tr>
                  <td colSpan={5} className="muted">
                    No API tokens yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>

      {revealed !== null && (
        <OneTimeSecretModal
          title="API token created"
          label="Token"
          value={revealed}
          onClose={() => setRevealed(null)}
        />
      )}
    </section>
  )
}
