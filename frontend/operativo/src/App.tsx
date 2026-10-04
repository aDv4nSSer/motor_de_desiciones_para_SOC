import { useEffect, useState } from 'react'
import { useAuth } from './auth/AuthContext'
import { canAccess, findRoute, homeFor } from './app/routes'
import type { RouteId } from './app/routes'
import { Forbidden } from './components/common'
import { Shell } from './components/Shell'
import { AlertsView } from './views/AlertsView'
import { ApprovalsView } from './views/ApprovalsView'
import { AuditView } from './views/AuditView'
import { CasesView } from './views/CasesView'
import { ComplianceView } from './views/ComplianceView'
import { LoginView } from './views/LoginView'
import { NodesView } from './views/NodesView'
import { TrendsView } from './views/TrendsView'
import { UsersView } from './views/UsersView'

const VIEWS: Record<RouteId, () => React.JSX.Element | null> = {
  alertas: AlertsView,
  aprobaciones: ApprovalsView,
  casos: CasesView,
  nodos: NodesView,
  auditoria: AuditView,
  usuarios: UsersView,
  cumplimiento: ComplianceView,
  tendencias: TrendsView,
}

function hashId(): string {
  return window.location.hash.replace('#', '')
}

export default function App() {
  const { user } = useAuth()
  const [hash, setHash] = useState(hashId)

  useEffect(() => {
    const onHash = () => setHash(hashId())
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  if (!user) return <LoginView />

  // Sin hash o con uno desconocido: la página de inicio del rol.
  const route = findRoute(hash) ?? findRoute(homeFor(user.role))!
  const allowed = canAccess(user.role, route)
  const View = VIEWS[route.id]

  return (
    <Shell current={allowed ? route : undefined} currentId={route.id}>
      {allowed
        ? <View key={route.id} />
        : <Forbidden needs={route.exact ? route.minRole : `${route.minRole} o superior`} />}
    </Shell>
  )
}
