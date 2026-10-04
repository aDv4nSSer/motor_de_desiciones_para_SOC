// Cliente HTTP del dashboard. Un solo lugar decide qué significa cada
// estado de sesión:
//   401 -> sesión inválida/revocada: la app vuelve al login.
//   503 -> el backend no pudo verificar la sesión (Redis caído): NO es un
//          login inválido; se conserva el token y se reintenta.
// El token vive solo en memoria (nunca localStorage).

export class ApiError extends Error {
  readonly status: number
  readonly detail: string

  constructor(status: number, detail: string) {
    super(detail || `HTTP ${status}`)
    this.status = status
    this.detail = detail
  }
}

/** 401 en una llamada protegida. */
export class SessionRevokedError extends ApiError {}

/** 503: no se pudo verificar la sesión; el token puede seguir siendo válido. */
export class SessionUnverifiableError extends ApiError {}

/** Sin respuesta HTTP (red caída, motor reiniciando). */
export class NetworkError extends Error {}

export interface SessionHooks {
  getToken: () => string | null
  onRevoked: () => void
  onUnverifiable: () => void
  onVerified: () => void
}

let hooks: SessionHooks | null = null

export function bindSession(h: SessionHooks | null): void {
  hooks = h
}

async function readDetail(resp: Response): Promise<string> {
  try {
    const body = await resp.json()
    if (typeof body?.detail === 'string') return body.detail
    if (typeof body?.error?.message === 'string') return body.error.message
  } catch {
    // cuerpo vacío o no-JSON: el status alcanza para clasificar el error
  }
  return ''
}

/** Llamada a un endpoint protegido. Lanza ApiError o una subclase. */
export async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = hooks?.getToken() ?? null
  const headers = new Headers(init.headers)
  if (token) headers.set('Authorization', `Bearer ${token}`)
  if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')

  let resp: Response
  try {
    resp = await fetch(path, { ...init, headers })
  } catch {
    throw new NetworkError('No se pudo contactar al motor')
  }

  if (resp.status === 401) {
    hooks?.onRevoked()
    throw new SessionRevokedError(401, await readDetail(resp))
  }
  if (resp.status === 503) {
    hooks?.onUnverifiable()
    throw new SessionUnverifiableError(503, await readDetail(resp))
  }
  if (!resp.ok) throw new ApiError(resp.status, await readDetail(resp))

  hooks?.onVerified()
  return (await resp.json()) as T
}

/** Login: no pasa por los hooks de sesión (un 401 acá es credencial inválida). */
export async function postLogin(username: string, password: string): Promise<Response> {
  return fetch('/api/v1/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  })
}

/** Cierre de sesión en el servidor (revoca el jti). Best-effort: nunca lanza. */
export async function postLogout(token: string): Promise<void> {
  try {
    await fetch('/api/v1/auth/logout', { method: 'POST', headers: { Authorization: `Bearer ${token}` } })
  } catch {
    // sin red: el token igual se descarta del navegador y expira con el JWT
  }
}
