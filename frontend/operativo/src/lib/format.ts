import { ROLE_LEVEL } from '../api/types'
import type { Role } from '../api/types'

const timeFmt = new Intl.DateTimeFormat('es-CL', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })
const dateTimeFmt = new Intl.DateTimeFormat('es-CL', {
  day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
})

/** Hora local; agrega la fecha si no es de hoy. */
export function formatTime(iso: string | null | undefined): string {
  if (!iso) return 'sin dato'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  const today = new Date()
  return d.toDateString() === today.toDateString() ? timeFmt.format(d) : dateTimeFmt.format(d)
}

export function formatScore(n: number | null | undefined): string {
  return typeof n === 'number' ? n.toFixed(3) : 'sin dato'
}

export function shortId(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id
}

export const ACCION_LABEL: Record<string, string> = {
  ninguna: 'Sin acción',
  ninguna_infra_propia: 'Sin acción (infra propia)',
  alertar_crear_caso: 'Alertar y crear caso',
  bloqueo_ip: 'Bloqueo de IP',
  alertar_pendiente_aprobacion: 'Pendiente de aprobación',
}

export function accionLabel(a: string | undefined): string {
  if (!a) return 'Sin evaluar'
  return ACCION_LABEL[a] ?? a
}

/** Nivel requerido efectivo, con el mismo fail-closed que el backend
 *  (main.py: un approval_level vacío o desconocido exige CISO). */
export function requiredLevel(level: string | null | undefined): Role {
  return level && level in ROLE_LEVEL ? (level as Role) : 'CISO'
}

export function roleReaches(role: Role, level: string | null | undefined): boolean {
  return ROLE_LEVEL[role] >= ROLE_LEVEL[requiredLevel(level)]
}
