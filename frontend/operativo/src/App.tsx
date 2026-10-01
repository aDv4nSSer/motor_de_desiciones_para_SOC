import { useEffect, useRef, useState } from 'react'
import { Bell, Briefcase, ShieldCheck, SignOut, UserCheck, WarningCircle } from '@phosphor-icons/react'
import type { Icon } from '@phosphor-icons/react'
import { useAuth } from './auth/AuthContext'
import { AlertsView } from './views/AlertsView'
import { ApprovalsView } from './views/ApprovalsView'
import { CasesView } from './views/CasesView'
import { LoginView } from './views/LoginView'

type ViewId = 'alertas' | 'aprobaciones' | 'casos'

const VIEWS: { id: ViewId; label: string; icon: Icon }[] = [
  { id: 'alertas', label: 'Alertas', icon: Bell },
  { id: 'aprobaciones', label: 'Aprobaciones', icon: UserCheck },
  { id: 'casos', label: 'Casos', icon: Briefcase },
]

function viewFromHash(): ViewId {
  const h = window.location.hash.replace('#', '')
  return VIEWS.some((v) => v.id === h) ? (h as ViewId) : 'alertas'
}

export default function App() {
  const { user, sessionState, logout } = useAuth()
  const [view, setView] = useState<ViewId>(viewFromHash)
  const mainRef = useRef<HTMLElement>(null)

  useEffect(() => {
    const onHash = () => setView(viewFromHash())
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  useEffect(() => {
    mainRef.current?.focus() // foco al contenido al cambiar de vista (lectores de pantalla)
  }, [view])

  if (!user) return <LoginView />

  return (
    <div className="shell">
      <a className="skip-link" href="#main">Saltar al contenido</a>
      <header className="topbar">
        <div className="brand">
          <ShieldCheck size={22} weight="duotone" aria-hidden="true" />
          <span className="brand-name">R-SOAR</span>
          <span className="muted">Operativo</span>
        </div>
        <nav aria-label="Secciones">
          <ul className="tabs">
            {VIEWS.map(({ id, label, icon: IconCmp }) => (
              <li key={id}>
                <a href={`#${id}`} className="tab" aria-current={view === id ? 'page' : undefined}>
                  <IconCmp size={18} aria-hidden="true" /> {label}
                </a>
              </li>
            ))}
          </ul>
        </nav>
        <div className="user">
          <span className="mono">{user.username}</span>
          <span className="badge badge-outline">{user.role}</span>
          <button type="button" className="btn btn-ghost btn-sm" onClick={logout}>
            <SignOut size={16} aria-hidden="true" /> Cerrar sesión
          </button>
        </div>
      </header>

      {sessionState === 'unverifiable' && (
        <div className="session-banner" role="status">
          <WarningCircle size={18} aria-hidden="true" />
          No se puede verificar tu sesión, reintentando. Los datos en pantalla pueden estar desactualizados.
        </div>
      )}

      <main id="main" ref={mainRef} tabIndex={-1} className="content">
        {view === 'alertas' && <AlertsView />}
        {view === 'aprobaciones' && <ApprovalsView />}
        {view === 'casos' && <CasesView />}
      </main>
    </div>
  )
}
