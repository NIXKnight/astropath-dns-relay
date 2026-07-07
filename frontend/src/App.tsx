// SPDX-License-Identifier: GPL-3.0-or-later
// astropath-dns-relay — self-hosted ACME DNS-01 solver gateway.
// Copyright (C) 2026  Saad Ali. Licensed under the GNU GPL v3 or later; see the
// LICENSE file in the project root, or <https://www.gnu.org/licenses/>.

import { Navigate, Route, Routes } from 'react-router'

import { AuthProvider, useAuth } from './auth/AuthProvider.tsx'
import { Layout } from './components/Layout.tsx'
import { BackendsPage } from './pages/BackendsPage.tsx'
import { DomainsPage } from './pages/DomainsPage.tsx'
import { EventsPage } from './pages/EventsPage.tsx'
import { LoginPage } from './pages/LoginPage.tsx'
import { TokensPage } from './pages/TokensPage.tsx'
import { TsigKeysPage } from './pages/TsigKeysPage.tsx'

// Layout route element: gate the whole console on the session probe. While the
// probe is in flight nothing renders; a 401 (unauthenticated or expired) routes
// to /login; otherwise the Layout renders and its <Outlet/> shows the page.
function RequireAuth(): React.JSX.Element {
  const { status } = useAuth()
  if (status === 'loading') {
    return <div className="app-loading">Loading…</div>
  }
  if (status === 'anonymous') {
    return <Navigate to="/login" replace />
  }
  return <Layout />
}

export function App(): React.JSX.Element {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route element={<RequireAuth />}>
          <Route index element={<Navigate to="/backends" replace />} />
          <Route path="/backends" element={<BackendsPage />} />
          <Route path="/backends/:id" element={<BackendsPage />} />
          <Route path="/domains" element={<DomainsPage />} />
          <Route path="/tsig-keys" element={<TsigKeysPage />} />
          <Route path="/tokens" element={<TokensPage />} />
          <Route path="/events" element={<EventsPage />} />
          <Route path="*" element={<Navigate to="/backends" replace />} />
        </Route>
      </Routes>
    </AuthProvider>
  )
}
