// SPDX-License-Identifier: GPL-3.0-or-later
// AstropathDNSRelay — self-hosted ACME DNS-01 solver gateway.
// Copyright (C) 2026  Saad Ali. Licensed under the GNU GPL v3 or later; see the
// LICENSE file in the project root, or <https://www.gnu.org/licenses/>.

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react'
import type { ReactNode } from 'react'

import { api, setUnauthorizedHandler } from '../api/client.ts'

type AuthStatus = 'loading' | 'authenticated' | 'anonymous'

interface AuthState {
  status: AuthStatus
  login: (password: string) => Promise<void>
  logout: () => Promise<void>
}

const AuthContext = createContext<AuthState | null>(null)

export function AuthProvider({
  children,
}: {
  children: ReactNode
}): React.JSX.Element {
  const [status, setStatus] = useState<AuthStatus>('loading')

  // A 401 from any call (e.g. an expired session mid-session) drops to login.
  useEffect(() => {
    setUnauthorizedHandler(() => setStatus('anonymous'))
    return () => setUnauthorizedHandler(null)
  }, [])

  // Probe the session once on load (GET /auth/session is behind require_admin).
  useEffect(() => {
    let cancelled = false
    api.get('/auth/session').then(
      () => {
        if (!cancelled) {
          setStatus('authenticated')
        }
      },
      () => {
        if (!cancelled) {
          setStatus('anonymous')
        }
      },
    )
    return () => {
      cancelled = true
    }
  }, [])

  const login = useCallback(async (password: string): Promise<void> => {
    await api.post('/auth/login', { password })
    setStatus('authenticated')
  }, [])

  const logout = useCallback(async (): Promise<void> => {
    try {
      await api.post('/auth/logout')
    } finally {
      setStatus('anonymous')
    }
  }, [])

  const value = useMemo<AuthState>(
    () => ({ status, login, logout }),
    [status, login, logout],
  )
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext)
  if (!ctx) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return ctx
}
