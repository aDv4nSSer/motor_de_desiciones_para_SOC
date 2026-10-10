import { ApiError, apiFetch, apiFetchRaw } from './client'
import type { Case, CasesPage, CaseState } from './types'

export const CASES_PAGE = 50

export interface CaseFilters {
  state: CaseState | 'todos'
  publicOnly: boolean
  sinceHours: number | null
}

export function casesPageUrl(f: CaseFilters, cursor = 0, limit = CASES_PAGE): string {
  const q = new URLSearchParams({ public_only: String(f.publicOnly), cursor: String(cursor), limit: String(limit) })
  if (f.state !== 'todos') q.set('state', f.state)
  if (f.sinceHours) q.set('since_hours', String(f.sinceHours))
  return `/api/v1/dashboard/cases/page?${q.toString()}`
}

export function fetchCasesPage(f: CaseFilters, cursor = 0): Promise<CasesPage> {
  return apiFetch<CasesPage>(casesPageUrl(f, cursor))
}

export type CaseUpdateOutcome =
  | { kind: 'done'; case: Case }
  | { kind: 'error'; message: string }

const STATUS_MESSAGE: Record<number, string> = {
  403: 'Tu rol no permite esta acción (el servidor la rechazó).',
  404: 'El caso ya no existe (expiró o se borró).',
  409: 'El caso cambió de estado mientras lo mirabas: actualiza y vuelve a intentar.',
  422: 'Falta la nota o el pedido no es válido.',
}

/** Cambio de estado de un caso. El servidor valida rol, transición y nota;
 *  acá solo se traduce su respuesta. */
export async function updateCaseState(caseId: string, state: CaseState, note: string): Promise<CaseUpdateOutcome> {
  try {
    const c = await apiFetch<Case>(`/api/v1/dashboard/cases/${encodeURIComponent(caseId)}/state`, {
      method: 'POST',
      body: JSON.stringify({ state, note }),
    })
    return { kind: 'done', case: c }
  } catch (e) {
    if (e instanceof ApiError) {
      const base = STATUS_MESSAGE[e.status] ?? `No se pudo actualizar el caso (HTTP ${e.status}).`
      return { kind: 'error', message: e.detail && e.status !== 422 ? `${base} ${e.detail}` : base }
    }
    return { kind: 'error', message: e instanceof Error ? e.message : 'No se pudo actualizar el caso' }
  }
}

/** Descarga el CSV de cierres (N2 y CISO; solo lectura). */
export async function downloadClosuresCsv(): Promise<void> {
  const resp = await apiFetchRaw('/api/v1/dashboard/cases/closures.csv')
  const blob = await resp.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `cierres_casos_${new Date().toISOString().slice(0, 10)}.csv`
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}
