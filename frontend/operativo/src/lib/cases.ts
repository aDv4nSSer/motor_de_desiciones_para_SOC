import type { Case, CaseState } from '../api/types'

export const CASE_STATE_LABEL: Record<CaseState, string> = {
  abierto: 'Abierto',
  en_investigacion: 'En investigación',
  cerrado_confirmado: 'Cerrado: confirmado',
  cerrado_falso_positivo: 'Cerrado: falso positivo',
}

/** Tier del caso: el caso automático de red solo nace de un T2 (kind
 *  network_t2_unconfirmed); el caso no guarda el tier, así que no se inventa
 *  para otros orígenes. */
export function caseTier(c: Case): number | null {
  return c.kind === 'network_t2_unconfirmed' ? 2 : null
}
