// SPDX-License-Identifier: GPL-3.0-or-later
// AstropathDNSRelay — self-hosted ACME DNS-01 solver gateway.
// Copyright (C) 2026  Saad Ali. Licensed under the GNU GPL v3 or later; see the
// LICENSE file in the project root, or <https://www.gnu.org/licenses/>.

import { NavLink, Outlet, useNavigate } from 'react-router'

import { useAuth } from '../auth/AuthProvider.tsx'

const NAV_ITEMS: ReadonlyArray<{ to: string; label: string }> = [
  { to: '/backends', label: 'Backends' },
  { to: '/domains', label: 'Domains' },
  { to: '/tsig-keys', label: 'TSIG Keys' },
  { to: '/tokens', label: 'API Tokens' },
  { to: '/events', label: 'Events' },
]

export function Layout(): React.JSX.Element {
  const { logout } = useAuth()
  const navigate = useNavigate()

  async function onLogout(): Promise<void> {
    await logout()
    navigate('/login', { replace: true })
  }

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-name">AstropathDNSRelay</span>
          <span className="brand-sub">DNS-01 solver gateway</span>
        </div>
        <nav className="nav">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                isActive ? 'nav-link nav-link-active' : 'nav-link'
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
        <button type="button" className="logout" onClick={() => void onLogout()}>
          Log out
        </button>
      </aside>
      <main className="content">
        <Outlet />
      </main>
    </div>
  )
}
