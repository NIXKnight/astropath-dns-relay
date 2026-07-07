// SPDX-License-Identifier: GPL-3.0-or-later
// AstropathDNSRelay — self-hosted ACME DNS-01 solver gateway.
// Copyright (C) 2026  Saad Ali. Licensed under the GNU GPL v3 or later; see the
// LICENSE file in the project root, or <https://www.gnu.org/licenses/>.

import { useCallback, useEffect, useRef, useState } from 'react'

import { errorMessage } from './format.ts'

export interface Resource<T> {
  data: T | null
  error: string | null
  loading: boolean
  reload: () => void
}

/**
 * Load an async resource on mount and on demand.
 *
 * The loader is held in a ref so an inline closure never re-triggers the fetch;
 * refetching happens only on mount and on ``reload()``. An in-flight fetch is
 * cancelled (ignored) when the component unmounts, so state is never set on a
 * dead component.
 */
export function useResource<T>(load: () => Promise<T>): Resource<T> {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [tick, setTick] = useState(0)

  const loadRef = useRef(load)
  loadRef.current = load

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    loadRef.current().then(
      (value) => {
        if (!cancelled) {
          setData(value)
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
  }, [tick])

  const reload = useCallback(() => setTick((value) => value + 1), [])
  return { data, error, loading, reload }
}
