// SPDX-License-Identifier: GPL-3.0-or-later
// astropath-dns-relay — self-hosted ACME DNS-01 solver gateway.
// Copyright (C) 2026  Saad Ali. Licensed under the GNU GPL v3 or later; see the
// LICENSE file in the project root, or <https://www.gnu.org/licenses/>.

// Same-origin fetch wrapper for the management API. The SPA is served from the
// same origin as /api/v1 (SPEC §9.3), so cookie credentials ride along and the
// backend's CSRF origin check (SPEC §8.4) passes for cookie-authenticated writes.
// No token or secret is ever stored here or in web storage — session state is the
// signed HttpOnly cookie the browser holds; reveal values live only in component
// memory (SPEC secret discipline).

const BASE = '/api/v1'

/** A non-2xx API response. ``detail`` is FastAPI's error body (string or list). */
export class ApiError extends Error {
  readonly status: number
  readonly detail: unknown

  constructor(status: number, detail: unknown) {
    super(typeof detail === 'string' ? detail : `request failed (${status})`)
    this.name = 'ApiError'
    this.status = status
    this.detail = detail
  }
}

// A single global hook lets the auth layer react to a 401 from *any* call
// (e.g. an expired session mid-session) by dropping to the login screen.
type UnauthorizedHandler = () => void
let onUnauthorized: UnauthorizedHandler | null = null

export function setUnauthorizedHandler(handler: UnauthorizedHandler | null): void {
  onUnauthorized = handler
}

async function parseBody(response: Response): Promise<unknown> {
  if (response.status === 204) {
    return null
  }
  const text = await response.text()
  if (!text) {
    return null
  }
  try {
    return JSON.parse(text) as unknown
  } catch {
    return text
  }
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
): Promise<T> {
  const init: RequestInit = {
    method,
    credentials: 'same-origin',
    headers: { Accept: 'application/json' },
  }
  if (body !== undefined) {
    init.headers = { ...init.headers, 'Content-Type': 'application/json' }
    init.body = JSON.stringify(body)
  }

  const response = await fetch(`${BASE}${path}`, init)
  const payload = await parseBody(response)

  if (!response.ok) {
    const detail =
      payload && typeof payload === 'object' && 'detail' in payload
        ? (payload as { detail: unknown }).detail
        : payload
    if (response.status === 401 && onUnauthorized) {
      onUnauthorized()
    }
    throw new ApiError(response.status, detail)
  }
  return payload as T
}

export const api = {
  get: <T>(path: string): Promise<T> => request<T>('GET', path),
  post: <T>(path: string, body?: unknown): Promise<T> =>
    request<T>('POST', path, body ?? {}),
  patch: <T>(path: string, body: unknown): Promise<T> =>
    request<T>('PATCH', path, body),
  del: (path: string): Promise<null> => request<null>('DELETE', path),
}
