import { useCallback, useEffect, useRef, useState } from 'react'
import { useAuth } from '../auth/AuthContext'
import { NetworkError, SessionRevokedError, SessionUnverifiableError } from '../api/client'

export const POLL_MS = 15_000
export const RETRY_MS = 5_000 // reintento más rápido mientras la sesión no se puede verificar

export interface PollState<T> {
  data: T | null
  error: string | null
  loading: boolean
  updatedAt: Date | null
  paused: boolean
  setPaused: (p: boolean) => void
  refresh: () => Promise<void>
}

/** Consulta periódica de una vista. Conserva el último dato bueno ante un
 *  error (no vacía la pantalla del operador por un fallo transitorio), pausa
 *  con la pestaña oculta y acelera el reintento si la sesión es 503. */
export function usePolling<T>(fetcher: () => Promise<T>): PollState<T> {
  const { sessionState } = useAuth()
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null)
  const [paused, setPaused] = useState(false)
  const fetcherRef = useRef(fetcher)
  useEffect(() => {
    fetcherRef.current = fetcher
  }, [fetcher])

  const refresh = useCallback(async () => {
    try {
      const result = await fetcherRef.current()
      setData(result)
      setError(null)
      setUpdatedAt(new Date())
    } catch (e) {
      if (e instanceof SessionRevokedError) return // la app ya vuelve al login
      if (e instanceof SessionUnverifiableError) setError(null) // lo informa el banner global
      else if (e instanceof NetworkError) setError('Sin conexión con el motor. Se muestran los últimos datos recibidos.')
      else setError(e instanceof Error ? e.message : 'Error desconocido')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  useEffect(() => {
    if (paused) return
    const ms = sessionState === 'unverifiable' ? RETRY_MS : POLL_MS
    const id = window.setInterval(() => {
      if (document.visibilityState === 'visible') void refresh()
    }, ms)
    return () => window.clearInterval(id)
  }, [paused, sessionState, refresh])

  return { data, error, loading, updatedAt, paused, setPaused, refresh }
}
