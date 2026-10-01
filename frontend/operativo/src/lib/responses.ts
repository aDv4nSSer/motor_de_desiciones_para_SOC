import type { ResponseRecord } from '../api/types'

/** Solo las entradas R1/R2 del stream de auditoría (descarta eventos de
 *  acceso y aprobaciones manuales), indexadas por trace_id. */
export function indexResponses(records: ResponseRecord[]): Map<string, ResponseRecord> {
  const map = new Map<string, ResponseRecord>()
  for (const r of records) {
    if (!r.trace_id || r.access_event || r.manual_approval) continue
    if (r.accion_recomendada === undefined && r.enrichment === undefined) continue
    if (!map.has(r.trace_id)) map.set(r.trace_id, r)
  }
  return map
}
