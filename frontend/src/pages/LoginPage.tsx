// SPDX-License-Identifier: GPL-3.0-or-later
// astropath-dns-relay — self-hosted ACME DNS-01 solver gateway.
// Copyright (C) 2026  Saad Ali. Licensed under the GNU GPL v3 or later; see the
// LICENSE file in the project root, or <https://www.gnu.org/licenses/>.

import { useState } from 'react'
import { Navigate, useNavigate } from 'react-router'

import { useAuth } from '../auth/AuthProvider.tsx'
import { errorMessage } from '../lib/format.ts'

export function LoginPage(): React.JSX.Element {
  const { status, login } = useAuth()
  const navigate = useNavigate()
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  if (status === 'authenticated') {
    return <Navigate to="/backends" replace />
  }

  async function onSubmit(event: React.FormEvent): Promise<void> {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await login(password)
      navigate('/backends', { replace: true })
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setBusy(false)
      setPassword('')
    }
  }

  return (
    <div className="login-screen">
      <form className="login-card" onSubmit={(event) => void onSubmit(event)}>
        <div className="brand brand-centered">
          <span className="brand-name">astropath-dns-relay</span>
          <span className="brand-sub">Admin sign-in</span>
        </div>
        {error && (
          <p className="notice notice-error" role="alert">
            {error}
          </p>
        )}
        <label className="field">
          <span>Admin password</span>
          <input
            type="password"
            autoFocus
            autoComplete="current-password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            required
          />
        </label>
        <button
          type="submit"
          className="primary"
          disabled={busy || password.length === 0}
        >
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  )
}
