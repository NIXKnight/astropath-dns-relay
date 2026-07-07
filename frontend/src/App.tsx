// SPDX-License-Identifier: GPL-3.0-or-later
// AstropathDNSRelay — self-hosted ACME DNS-01 solver gateway.
// Copyright (C) 2026  Saad Ali. Licensed under the GNU GPL v3 or later; see the
// LICENSE file in the project root, or <https://www.gnu.org/licenses/>.

import { Route, Routes } from 'react-router'

// T-M4-01 scaffold shell. The admin screens (login, backends/domains/tsig/token
// CRUD, events) and their auth gating are wired in T-M4-02.
export function App(): React.JSX.Element {
  return (
    <Routes>
      <Route
        path="*"
        element={
          <main className="app-shell">
            <h1>AstropathDNSRelay</h1>
            <p>Admin console — scaffold. Screens land in T-M4-02.</p>
          </main>
        }
      />
    </Routes>
  )
}
