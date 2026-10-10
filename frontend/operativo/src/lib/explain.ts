import { useEffect, useState } from 'react'
import { ApiError, apiFetch } from '../api/client'
import type { AttackInfo, ExplainTrace, Role } from '../api/types'
import { ROLE_LEVEL } from '../api/types'

export const EXPLAIN_NOTE = 'Reglas explicativas v1; SHAP pendiente.'

export type ExplainLoad =
  | { kind: 'loading' }
  | { kind: 'ok'; trace: ExplainTrace }
  | { kind: 'missing' }
  | { kind: 'error'; message: string }

/** La traza la sirve un endpoint N2 (mismo permiso que el historial parcial). */
export function canExplain(role: Role): boolean {
  return ROLE_LEVEL[role] >= ROLE_LEVEL.N2
}

export function useExplain(traceId: string | undefined, role: Role): ExplainLoad | null {
  const [load, setLoad] = useState<ExplainLoad>({ kind: 'loading' })
  const allowed = canExplain(role)
  useEffect(() => {
    if (!traceId || !allowed) return
    let alive = true
    apiFetch<ExplainTrace>(`/api/v1/dashboard/explain/${encodeURIComponent(traceId)}`)
      .then((trace) => { if (alive) setLoad({ kind: 'ok', trace }) })
      .catch((e: unknown) => {
        if (!alive) return
        if (e instanceof ApiError && e.status === 404) setLoad({ kind: 'missing' })
        else setLoad({ kind: 'error', message: e instanceof Error ? e.message : 'No se pudo leer la traza' })
      })
    return () => { alive = false }
  }, [traceId, allowed])
  if (!traceId || !allowed) return null
  return load
}

export function attackText(a: AttackInfo | undefined): string {
  if (!a) return 'sin dato'
  if (a.tecnica) return `${a.tecnica}${a.tecnica_nombre ? ` ${a.tecnica_nombre}` : ''}${a.classtype ? ` (classtype ${a.classtype})` : ''}`
  return a.nota ?? 'sin mapeo'
}
