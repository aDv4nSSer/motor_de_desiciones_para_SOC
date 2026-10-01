import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { bindSession, postLogin } from '../api/client'
import type { LoginResponse, Me } from '../api/types'

export type SessionState = 'ok' | 'unverifiable'

export type LoginOutcome =
  | { ok: true }
  | { ok: false; kind: 'credentials' | 'unavailable' | 'network' | 'other'; message: string }

interface AuthValue {
  user: Me | null
  sessionState: SessionState
  /** Motivo por el que se volvió al login (sesión revocada/expirada). */
  logoutReason: string | null
  login: (username: string, password: string) => Promise<LoginOutcome>
  logout: () => void
}

const AuthContext = createContext<AuthValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  // El token vive solo en este ref (memoria del proceso). Se pierde al
  // refrescar la página: aceptado para esta versión, sin localStorage.
  const tokenRef = useRef<string | null>(null)
  const [user, setUser] = useState<Me | null>(null)
  const [sessionState, setSessionState] = useState<SessionState>('ok')
  const [logoutReason, setLogoutReason] = useState<string | null>(null)

  const clear = useCallback((reason: string | null) => {
    tokenRef.current = null
    setUser(null)
    setSessionState('ok')
    setLogoutReason(reason)
  }, [])

  useEffect(() => {
    bindSession({
      getToken: () => tokenRef.current,
      onRevoked: () => {
        if (tokenRef.current) clear('Tu sesión expiró o fue revocada. Inicia sesión de nuevo.')
      },
      onUnverifiable: () => setSessionState('unverifiable'),
      onVerified: () => setSessionState('ok'),
    })
    return () => bindSession(null)
  }, [clear])

  const login = useCallback(async (username: string, password: string): Promise<LoginOutcome> => {
    let resp: Response
    try {
      resp = await postLogin(username, password)
    } catch {
      return { ok: false, kind: 'network', message: 'No se pudo contactar al motor. Revisa la conexión y reintenta.' }
    }
    if (resp.status === 401) {
      return { ok: false, kind: 'credentials', message: 'Usuario o contraseña incorrectos.' }
    }
    if (resp.status === 503 || resp.status === 500) {
      return {
        ok: false,
        kind: 'unavailable',
        message: 'El motor no pudo verificar las credenciales en este momento. Reintenta en unos segundos.',
      }
    }
    if (!resp.ok) {
      return { ok: false, kind: 'other', message: `No se pudo iniciar sesión (HTTP ${resp.status}).` }
    }
    const body = (await resp.json()) as LoginResponse
    tokenRef.current = body.access_token
    setLogoutReason(null)
    setSessionState('ok')
    setUser({ username, role: body.role })
    return { ok: true }
  }, [])

  const logout = useCallback(() => clear(null), [clear])

  const value = useMemo(
    () => ({ user, sessionState, logoutReason, login, logout }),
    [user, sessionState, logoutReason, login, logout],
  )
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth fuera de AuthProvider')
  return ctx
}
