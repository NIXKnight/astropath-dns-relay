// SPDX-License-Identifier: GPL-3.0-or-later
// astropath-dns-relay — self-hosted ACME DNS-01 solver gateway.
// Copyright (C) 2026  Saad Ali. Licensed under the GNU GPL v3 or later; see the
// LICENSE file in the project root, or <https://www.gnu.org/licenses/>.

import { ApiError } from '../api/client.ts'

/** Best-effort human message from an unknown thrown value (never a secret). */
export function errorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    const { detail } = err
    if (typeof detail === 'string') {
      return detail
    }
    if (Array.isArray(detail)) {
      // FastAPI validation errors: [{loc, msg, type}, …] — join the messages;
      // the backend deliberately omits submitted values, so nothing leaks here.
      return detail
        .map((item) =>
          item && typeof item === 'object' && 'msg' in item
            ? String((item as { msg: unknown }).msg)
            : JSON.stringify(item),
        )
        .join('; ')
    }
    return `request failed (${err.status})`
  }
  if (err instanceof Error) {
    return err.message
  }
  return 'unexpected error'
}

/** Render an ISO timestamp in the viewer's locale, tolerating bad input. */
export function formatTimestamp(iso: string | null | undefined): string {
  if (!iso) {
    return '—'
  }
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) {
    return iso
  }
  return date.toLocaleString()
}
