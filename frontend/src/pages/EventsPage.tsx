// SPDX-License-Identifier: GPL-3.0-or-later
// AstropathDNSRelay — self-hosted ACME DNS-01 solver gateway.
// Copyright (C) 2026  Saad Ali. Licensed under the GNU GPL v3 or later; see the
// LICENSE file in the project root, or <https://www.gnu.org/licenses/>.

import { useEffect, useState } from 'react'

import { api } from '../api/client.ts'
import type { ChallengeEventPage } from '../api/types.ts'
import { errorMessage, formatTimestamp } from '../lib/format.ts'

const LIMIT = 50

export function EventsPage(): React.JSX.Element {
  const [offset, setOffset] = useState(0)
  const [page, setPage] = useState<ChallengeEventPage | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [nonce, setNonce] = useState(0)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    api.get<ChallengeEventPage>(`/events?limit=${LIMIT}&offset=${offset}`).then(
      (result) => {
        if (!cancelled) {
          setPage(result)
          setError(null)
          setLoading(false)
        }
      },
      (err: unknown) => {
        if (!cancelled) {
          setError(errorMessage(err))
          setLoading(false)
        }
      },
    )
    return () => {
      cancelled = true
    }
  }, [offset, nonce])

  const total = page?.total ?? 0
  const items = page?.items ?? []
  const hasPrev = offset > 0
  const hasNext = offset + LIMIT < total
  const rangeStart = total === 0 ? 0 : offset + 1
  const rangeEnd = Math.min(offset + LIMIT, total)

  return (
    <section className="page">
      <header className="page-head">
        <h1>Events</h1>
        <p className="muted">
          Append-only audit of every challenge (present / cleanup). Read-only; no
          secrets are recorded.
        </p>
      </header>

      <div className="card">
        <div className="toolbar">
          <span className="muted">
            {total === 0 ? 'No events' : `${rangeStart}–${rangeEnd} of ${total}`}
          </span>
          <div className="spacer" />
          <button type="button" onClick={() => setNonce((value) => value + 1)}>
            Refresh
          </button>
          <button
            type="button"
            disabled={!hasPrev}
            onClick={() => setOffset((value) => Math.max(0, value - LIMIT))}
          >
            Previous
          </button>
          <button
            type="button"
            disabled={!hasNext}
            onClick={() => setOffset((value) => value + LIMIT)}
          >
            Next
          </button>
        </div>

        {error && <p className="notice notice-error">{error}</p>}
        {loading && !page ? (
          <p className="muted">Loading…</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Zone</th>
                <th>Record</th>
                <th>Action</th>
                <th>Provider</th>
                <th>Result</th>
                <th>Latency</th>
                <th>Source</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {items.map((event) => (
                <tr key={event.id}>
                  <td className="nowrap">{formatTimestamp(event.ts)}</td>
                  <td>
                    <code>{event.zone}</code>
                  </td>
                  <td>
                    <code>{event.record_name}</code>
                  </td>
                  <td>{event.action}</td>
                  <td>{event.provider}</td>
                  <td>
                    <span
                      className={
                        event.result === 'ok' ? 'pill pill-ok' : 'pill pill-err'
                      }
                    >
                      {event.result}
                    </span>
                  </td>
                  <td>{event.latency_ms} ms</td>
                  <td className="mono small">{event.source}</td>
                  <td className="muted small">{event.error_detail ?? '—'}</td>
                </tr>
              ))}
              {items.length === 0 && (
                <tr>
                  <td colSpan={9} className="muted">
                    No events recorded yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>
    </section>
  )
}
