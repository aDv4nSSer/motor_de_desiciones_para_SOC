import { ApiError, NetworkError, SessionRevokedError, SessionUnverifiableError, apiFetch } from './client'
import type { Approval, Role } from './types'
import { requiredLevel } from '../lib/format'

type Decision = 'approved' | 'rejected'

export type ResolveOutcome =
  | { kind: 'done'; approval: Approval }
  | { kind: 'forbidden' | 'conflict' | 'gone' | 'unverifiable' | 'error'; message: string }

/** POST de resolución y traducción de cada respuesta real del servidor. */
export async function resolveApproval(traceId: string, decision: Decision, role: Role, level: string): Promise<ResolveOutcome> {
  try {
    const approval = await apiFetch<Approval>(
      `/api/v1/dashboard/approvals/${encodeURIComponent(traceId)}/resolve`,
      { method: 'POST', body: JSON.stringify({ decision, note: '' }) },
    )
    return { kind: 'done', approval }
  } catch (e) {
    if (e instanceof SessionRevokedError) throw e // la app vuelve al login
    if (e instanceof SessionUnverifiableError) {
      return { kind: 'unverifiable', message: 'No se pudo verificar tu sesión. No se aplicó ningún cambio; reintenta en unos segundos.' }
    }
    if (e instanceof NetworkError) {
      return { kind: 'error', message: 'Sin conexión con el motor. No se sabe si la resolución se aplicó: actualiza la lista antes de reintentar.' }
    }
    if (e instanceof ApiError) {
      if (e.status === 403) {
        return { kind: 'forbidden', message: `Tu rol (${role}) no alcanza para este nivel (requiere ${requiredLevel(level)}).` }
      }
      if (e.status === 409 && e.detail.includes('expiró')) {
        return { kind: 'gone', message: 'La aprobación expiró (más de 4 h sin resolver). Si la amenaza sigue, un evento nuevo abrirá otra.' }
      }
      if (e.status === 409) return { kind: 'conflict', message: 'Ya fue resuelta por otro operador.' }
      if (e.status === 422) return { kind: 'forbidden', message: e.detail || 'El servidor no permite aprobar esta acción.' }
      if (e.status === 404) return { kind: 'gone', message: 'La aprobación ya no existe.' }
      return { kind: 'error', message: `El motor no pudo resolverla (HTTP ${e.status}). No se aplicó ningún cambio confirmado; reintenta.` }
    }
    return { kind: 'error', message: 'Error inesperado al resolver.' }
  }
}
