import type { ResponseRecord } from '../api/types'
import { ROLE_LEVEL } from '../api/types'
import { accionLabel } from './format'

/** Prefijos de BlockResult.reason que escribe R2 (motor/response/enforcer.py,
 *  worker.py y el STALE_PREFIX de explain.py). */
const REASON = {
  alreadyBlocked: 'ya bloqueada',
  ttlExtended: 'TTL extendido',
  safelist: 'safelisted',
  stale: 'stale_backlog',
  dryRun: 'dry_run',
} as const

/** Acción de R2 para mostrar, derivada del registro de respuesta (H60).
 *
 *  `accion_recomendada` sola no alcanza: el worker guarda `ninguna` para todo
 *  resultado de respond_block que no sea un bloqueo nuevo (ya bloqueada con
 *  TTL extendido, safelist, dry_run), y la tabla mostraba "Sin acción" en T3
 *  que R2 sí había resuelto. Esto es solo presentación: no cambia ninguna
 *  decisión ni lo que se guarda. */
export function accionR2Label(r: ResponseRecord): string {
  const a = r.accion_recomendada
  const b = r.block ?? {}
  const reason = b.reason ?? ''
  if (a === 'ninguna_infra_propia' || reason.startsWith(REASON.safelist)) return 'Infra propia, sin caso'
  if (reason.startsWith(REASON.alreadyBlocked)) {
    return reason.includes(REASON.ttlExtended) ? 'Ya bloqueada (TTL extendido)' : 'Ya bloqueada'
  }
  if (reason.startsWith(REASON.dryRun)) return 'Bloqueo simulado (dry_run, no ejecutado)'
  if (a === 'bloqueo_ip') {
    if (reason.startsWith(REASON.stale)) return 'Bloqueo recomendado, no ejecutado (evento antiguo)'
    return b.action === 'block' && b.enforced === false ? 'Bloqueo automático (ejecución no confirmada)' : 'Bloqueo automático'
  }
  if (a === 'alertar_pendiente_aprobacion') {
    if (reason.startsWith(REASON.stale)) return 'Aprobación recomendada, no creada (evento antiguo)'
    const level = b.approval_level && b.approval_level in ROLE_LEVEL ? b.approval_level : null
    return level ? `Pendiente de aprobación ${level}` : 'Pendiente de aprobación (nivel sin dato)'
  }
  if (a === 'alertar_crear_caso') return r.case_id ? 'Alertar y crear caso' : 'Alertar, sin caso'
  return accionLabel(a)
}
