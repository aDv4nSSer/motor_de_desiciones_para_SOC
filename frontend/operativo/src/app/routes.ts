import {
  Bell, Briefcase, ChartLineUp, ClipboardText, Fingerprint, HardDrives, UserCheck, UsersThree,
} from '@phosphor-icons/react'
import type { Icon } from '@phosphor-icons/react'
import { ROLE_LEVEL } from '../api/types'
import type { Role } from '../api/types'

// Una sola tabla decide qué ve cada rol. La usan el menú (qué se lista) y el
// guardia de ruta (qué se renderiza): escribir #usuarios a mano como N1 no
// muestra la vista ni dispara sus llamadas. El backend aplica las mismas
// reglas (require_role / require_ciso en motor/main.py): esto es UX, aquel el
// control real.

export type RouteId =
  | 'alertas' | 'aprobaciones' | 'casos' | 'nodos'
  | 'auditoria' | 'usuarios' | 'cumplimiento' | 'tendencias'

export interface RouteDef {
  id: RouteId
  label: string
  /** Título de la página (header). */
  title: string
  icon: Icon
  section: 'Operación' | 'Gobierno'
  /** Rol mínimo (jerárquico N1 < N2 < CISO). */
  minRole: Role
  /** true: solo ese rol exacto (reportes de cumplimiento, como require_ciso). */
  exact?: boolean
}

export const ROUTES: RouteDef[] = [
  { id: 'alertas', label: 'Alertas', title: 'Alertas T2 y T3', icon: Bell, section: 'Operación', minRole: 'N1' },
  { id: 'aprobaciones', label: 'Aprobaciones', title: 'Aprobaciones pendientes', icon: UserCheck, section: 'Operación', minRole: 'N1' },
  { id: 'casos', label: 'Casos', title: 'Gestión interna de casos', icon: Briefcase, section: 'Operación', minRole: 'N1' },
  { id: 'nodos', label: 'Estado de nodos', title: 'Estado de nodos y servicios', icon: HardDrives, section: 'Operación', minRole: 'N1' },
  { id: 'auditoria', label: 'Historial y auditoría', title: 'Historial y auditoría', icon: Fingerprint, section: 'Gobierno', minRole: 'N2' },
  { id: 'usuarios', label: 'Usuarios y sesiones', title: 'Usuarios y sesiones', icon: UsersThree, section: 'Gobierno', minRole: 'N2' },
  { id: 'cumplimiento', label: 'Cumplimiento', title: 'Cumplimiento Ley 21.663', icon: ClipboardText, section: 'Gobierno', minRole: 'CISO', exact: true },
  { id: 'tendencias', label: 'Tendencias', title: 'Tendencias', icon: ChartLineUp, section: 'Gobierno', minRole: 'CISO', exact: true },
]

export function canAccess(role: Role, route: RouteDef): boolean {
  return route.exact ? role === route.minRole : ROLE_LEVEL[role] >= ROLE_LEVEL[route.minRole]
}

export function routesFor(role: Role): RouteDef[] {
  return ROUTES.filter((r) => canAccess(role, r))
}

/** Página de inicio por rol: el CISO entra a su resumen de cumplimiento. */
export function homeFor(role: Role): RouteId {
  return role === 'CISO' ? 'cumplimiento' : 'alertas'
}

export function findRoute(id: string): RouteDef | undefined {
  return ROUTES.find((r) => r.id === id)
}
