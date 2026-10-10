import { useCallback, useEffect, useState } from 'react'

export type ApiHealth =
  | { state: 'loading' }
  | { state: 'online'; version: string }
  | { state: 'offline'; error: string }

const TIMEOUT_MS = 5000

/** Asks the backend GET /api/health whether it is running. */
export function useApiHealth(): { health: ApiHealth; retry: () => void } {
  const [health, setHealth] = useState<ApiHealth>({ state: 'loading' })
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    let cancelled = false
    const controller = new AbortController()
    const timer = window.setTimeout(() => controller.abort(), TIMEOUT_MS)

    fetch('/api/health', { signal: controller.signal })
      .then(async (res) => {
        if (!res.ok) throw new Error(`The API answered with HTTP ${res.status}`)
        const body = (await res.json()) as { status?: string; version?: string }
        if (body.status !== 'ok') throw new Error('The API gave an unexpected answer')
        if (!cancelled) setHealth({ state: 'online', version: body.version ?? '' })
      })
      .catch((err: unknown) => {
        if (cancelled) return
        const timedOut = err instanceof Error && err.name === 'AbortError'
        setHealth({
          state: 'offline',
          error: timedOut ? 'No answer from the API' : err instanceof Error ? err.message : 'Unknown error',
        })
      })
      .finally(() => window.clearTimeout(timer))

    return () => {
      cancelled = true
      window.clearTimeout(timer)
      controller.abort()
    }
  }, [attempt])

  const retry = useCallback(() => {
    setHealth({ state: 'loading' })
    setAttempt((n) => n + 1)
  }, [])

  return { health, retry }
}
