// SPDX-License-Identifier: GPL-3.0-or-later
// AstropathDNSRelay — self-hosted ACME DNS-01 solver gateway.
// Copyright (C) 2026  Saad Ali. Licensed under the GNU GPL v3 or later; see the
// LICENSE file in the project root, or <https://www.gnu.org/licenses/>.

import { useCallback, useState } from 'react'

import { api } from '../api/client.ts'
import type { TsigKeyCreated, TsigKeyRead } from '../api/types.ts'
import { OneTimeSecretModal } from '../components/OneTimeSecretModal.tsx'
import { errorMessage, formatTimestamp } from '../lib/format.ts'
import { useResource } from '../lib/useResource.ts'

const ALGORITHMS = ['hmac-sha256', 'hmac-sha384', 'hmac-sha512', 'hmac-sha224', 'hmac-sha1']

export function TsigKeysPage(): React.JSX.Element {
  const load = useCallback(() => api.get<TsigKeyRead[]>('/tsig-keys'), [])
  const { data, error, loading, reload } = useResource(load)

  const [name, setName] = useState('')
  const [algorithm, setAlgorithm] = useState('hmac-sha256')
  const [formError, setFormError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [revealed, setRevealed] = useState<string | null>(null)

  async function onCreate(event: React.FormEvent): Promise<void> {
    event.preventDefault()
    setFormError(null)
    setBusy(true)
    try {
      const created = await api.post<TsigKeyCreated>('/tsig-keys', { name, algorithm })
      setRevealed(created.secret) // shown once, held only in memory
      setName('')
      setAlgorithm('hmac-sha256')
      reload()
    } catch (err) {
      setFormError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  async function onRevoke(key: TsigKeyRead): Promise<void> {
    if (!window.confirm(`Revoke TSIG key "${key.name}"? This cannot be undone.`)) {
      return
    }
    try {
      await api.del(`/tsig-keys/${key.id}`)
      reload()
    } catch (err) {
      window.alert(errorMessage(err))
    }
  }

  return (
    <section className="page">
      <header className="page-head">
        <h1>TSIG Keys</h1>
        <p className="muted">
          cert-manager authenticates DNS UPDATEs with these keys. The secret is
          shown once at creation; a lost secret is revoked and recreated.
        </p>
      </header>

      <form className="card form-grid" onSubmit={(event) => void onCreate(event)}>
        <h2>Generate a key</h2>
        {formError && (
          <p className="notice notice-error" role="alert">
            {formError}
          </p>
        )}
        <label className="field">
          <span>Name (cert-manager tsigKeyName)</span>
          <input
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder="cm-key."
            required
          />
        </label>
        <label className="field">
          <span>Algorithm</span>
          <select
            value={algorithm}
            onChange={(event) => setAlgorithm(event.target.value)}
          >
            {ALGORITHMS.map((algo) => (
              <option key={algo} value={algo}>
                {algo}
              </option>
            ))}
          </select>
        </label>
        <div className="form-actions">
          <button type="submit" className="primary" disabled={busy}>
            {busy ? 'Generating…' : 'Generate key'}
          </button>
        </div>
      </form>

      <div className="card">
        <h2>Keys</h2>
        {error && <p className="notice notice-error">{error}</p>}
        {loading && !data ? (
          <p className="muted">Loading…</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Name</th>
                <th>Algorithm</th>
                <th>Created</th>
                <th aria-label="Actions" />
              </tr>
            </thead>
            <tbody>
              {(data ?? []).map((key) => (
                <tr key={key.id}>
                  <td>{key.id}</td>
                  <td>
                    <code>{key.name}</code>
                  </td>
                  <td>{key.algorithm}</td>
                  <td>{formatTimestamp(key.created_at)}</td>
                  <td className="row-actions">
                    <button
                      type="button"
                      className="danger"
                      onClick={() => void onRevoke(key)}
                    >
                      Revoke
                    </button>
                  </td>
                </tr>
              ))}
              {(data ?? []).length === 0 && (
                <tr>
                  <td colSpan={5} className="muted">
                    No TSIG keys yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>

      {revealed !== null && (
        <OneTimeSecretModal
          title="TSIG key created"
          label="Secret (base64 BIND form)"
          value={revealed}
          onClose={() => setRevealed(null)}
        />
      )}
    </section>
  )
}
