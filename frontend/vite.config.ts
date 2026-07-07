// SPDX-License-Identifier: GPL-3.0-or-later
// astropath-dns-relay — self-hosted ACME DNS-01 solver gateway.
// Copyright (C) 2026  Saad Ali. Licensed under the GNU GPL v3 or later; see the
// LICENSE file in the project root, or <https://www.gnu.org/licenses/>.

import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// The admin SPA is served same-origin by the FastAPI backend in production
// (SPEC §9.3): built to dist/ and mounted behind an explicit catch-all. In dev
// the Vite server proxies the API and ops routes to the backend so the browser
// stays same-origin (credentialed cookies + the CSRF origin check both pass).
const BACKEND = 'http://localhost:8080'
const proxied = ['/api', '/healthz', '/readyz', '/metrics', '/openapi.json', '/docs', '/redoc']

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  build: {
    // Emitted into frontend/dist/ (index.html + assets/*), copied verbatim into
    // the runtime image and served from /app/static (Dockerfile, T-M4-05).
    outDir: 'dist',
    assetsDir: 'assets',
  },
  server: {
    port: 5173,
    proxy: Object.fromEntries(
      proxied.map((path) => [path, { target: BACKEND, changeOrigin: true }]),
    ),
  },
})
