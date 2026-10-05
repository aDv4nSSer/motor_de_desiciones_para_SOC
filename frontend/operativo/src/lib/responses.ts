import { apiFetch, SessionRevokedError, SessionUnverifiableError } from '../api/client'
import type { Decision, ResponseLookup, ResponseRecord } from '../api/types'

/** = RESPONSE_LOOKUP_MAX_IDS del backend (dashboard.py). */
export const LOOKUP_MAX_IDS = 100

/** Una tarea entregada al worker en el último lote puede seguir procesándose
 *  (lotes de 16, TI con timeout de 4 s): hasta este margen detrás de la
 *  frontera del worker, la ausencia de registro todavía es "en proceso". */
export const PROCESSING_GRACE_MS = 60_000

/** Resultado de la última consulta de respuesta para un trace_id. */
export interface RowLookup {
  record?: ResponseRecord
  /** La consulta cubrió todas las fuentes: la ausencia es afirmable. */
  complete: boolean
  /** La consulta misma falló (red, 5xx). */
  failed: boolean
  frontierMs: number | null
  checkedAt: number
}

export type ResponseState =
  | { kind: 'ok'; record: ResponseRecord }
  | { kind: 'checking' }
  | { kind: 'processing' }
  | { kind: 'missing' }
  | { kind: 'error' }

/** Resuelve la respuesta R1/R2 de trace_id concretos (en tandas del máximo
 *  del backend). Un fallo de la consulta queda marcado por fila, sin romper
 *  la vista; los errores de sesión sí se propagan (los maneja usePolling). */
export async function lookupResponses(ids: string[], now = Date.now()): Promise<Map<string, RowLookup>> {
  const out = new Map<string, RowLookup>()
  const unique = [...new Set(ids)]
  for (let i = 0; i < unique.length; i += LOOKUP_MAX_IDS) {
    const chunk = unique.slice(i, i + LOOKUP_MAX_IDS)
    let res: ResponseLookup | null = null
    try {
      res = await apiFetch<ResponseLookup>('/api/v1/dashboard/responses/lookup', {
        method: 'POST',
        body: JSON.stringify({ trace_ids: chunk }),
      })
    } catch (e) {
      if (e instanceof SessionRevokedError || e instanceof SessionUnverifiableError) throw e
    }
    const frontierMs = res?.worker_frontier ? Date.parse(res.worker_frontier) : null
    for (const id of chunk) {
      out.set(id, {
        record: res?.responses[id],
        complete: res?.complete ?? false,
        failed: res === null,
        frontierMs,
        checkedAt: now,
      })
    }
  }
  return out
}

/** Un registro ya encontrado no se pierde por una consulta posterior que falle. */
export function mergeLookups(prev: Map<string, RowLookup>, next: Map<string, RowLookup>): Map<string, RowLookup> {
  const merged = new Map(prev)
  for (const [id, l] of next) {
    if (merged.get(id)?.record) continue
    merged.set(id, l)
  }
  return merged
}

/** Estado de la respuesta de una decisión: separa "en proceso" (el worker aún
 *  no llega o está en ese lote), "sin registro" (el worker ya pasó y no hay
 *  registro: anomalía) y "error" (no se puede afirmar nada). */
export function responseState(d: Decision, l: RowLookup | undefined): ResponseState {
  if (!l) return { kind: 'checking' }
  if (l.record) return { kind: 'ok', record: l.record }
  if (l.failed || !l.complete) return { kind: 'error' }
  const frontier = l.frontierMs ?? l.checkedAt
  return Date.parse(d.timestamp) >= frontier - PROCESSING_GRACE_MS ? { kind: 'processing' } : { kind: 'missing' }
}
