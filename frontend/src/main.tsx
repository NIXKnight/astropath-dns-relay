// SPDX-License-Identifier: GPL-3.0-or-later
// AstropathDNSRelay — self-hosted ACME DNS-01 solver gateway.
// Copyright (C) 2026  Saad Ali. Licensed under the GNU GPL v3 or later; see the
// LICENSE file in the project root, or <https://www.gnu.org/licenses/>.

import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router'

import { App } from './App.tsx'
import './index.css'

const container = document.getElementById('root')
if (!container) {
  throw new Error('root element #root is missing from index.html')
}

// BrowserRouter (history API) so deep links like /backends/5 work; the backend
// serves index.html for any non-API path (SPEC §9.3) and the router takes over.
createRoot(container).render(
  <StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </StrictMode>,
)
