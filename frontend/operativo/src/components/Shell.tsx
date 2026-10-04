import { useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { List, ShieldCheck, SignOut, WarningCircle, X } from '@phosphor-icons/react'
import uboLogo from '../assets/brand/ubo-logo-provisional.png'
import { useAuth } from '../auth/AuthContext'
import { routesFor } from '../app/routes'
import type { RouteDef, RouteId } from '../app/routes'

const ROLE_NAME = { N1: 'Operador N1', N2: 'Operador N2', CISO: 'CISO / Gerencia' } as const

interface ShellProps {
  current: RouteDef | undefined
  currentId: RouteId | string
  children: ReactNode
}

/** Layout único (header + sidebar) para todas las páginas. El menú se arma
 *  con las rutas que el rol del JWT puede abrir (routes.ts). */
export function Shell({ current, currentId, children }: ShellProps) {
  const { user, sessionState, logout } = useAuth()
  const [navOpen, setNavOpen] = useState(false)
  const mainRef = useRef<HTMLElement>(null)

  useEffect(() => {
    mainRef.current?.focus() // foco al contenido al cambiar de vista (lectores de pantalla)
  }, [currentId])

  if (!user) return null
  const routes = routesFor(user.role)
  const sections = [...new Set(routes.map((r) => r.section))]

  return (
    <div className="app" data-nav-open={navOpen}>
      <a className="skip-link" href="#main">Saltar al contenido</a>

      <div className="app-brand">
        <span className="brand-plate">
          {/* Identidad provisional: logo de la Universidad Bernardo O'Higgins
              hasta que R-SOAR tenga marca propia (ver README). */}
          <img src={uboLogo} alt="Universidad Bernardo O'Higgins" />
        </span>
      </div>

      <header className="app-header">
        <button
          type="button" className="btn btn-icon menu-toggle"
          aria-expanded={navOpen} aria-controls="app-nav"
          aria-label={navOpen ? 'Cerrar menú' : 'Abrir menú'}
          onClick={() => setNavOpen(!navOpen)}
        >
          {navOpen ? <X size={20} aria-hidden="true" /> : <List size={20} aria-hidden="true" />}
        </button>
        <div className="crumbs">
          <span className="product">R-SOAR</span>
          <span className="sep" aria-hidden="true">/</span>
          <span className="here">{current ? `${current.section}, ${current.label}` : 'Acceso restringido'}</span>
        </div>
        <div className="user">
          <div className="user-id">
            <span className="name mono">{user.username}</span>
            <span className="role">{ROLE_NAME[user.role]}</span>
          </div>
          <button type="button" className="btn btn-secondary btn-sm" onClick={logout}>
            <SignOut size={16} aria-hidden="true" /> Cerrar sesión
          </button>
        </div>
      </header>

      <nav id="app-nav" className="app-side" aria-label="Secciones">
        {sections.map((section) => (
          <div className="nav-section" key={section}>
            <p className="nav-label" id={`nav-${section}`}>{section}</p>
            <ul className="nav-list" aria-labelledby={`nav-${section}`}>
              {routes.filter((r) => r.section === section).map(({ id, label, icon: IconCmp }) => (
                <li key={id}>
                  <a href={`#${id}`} className="nav-link" aria-current={currentId === id ? 'page' : undefined}
                     onClick={() => setNavOpen(false)}>
                    <IconCmp size={20} weight={currentId === id ? 'fill' : 'regular'} aria-hidden="true" />
                    {label}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        ))}
        <div className="side-foot">
          <ShieldCheck size={14} aria-hidden="true" /> Acceso según rol: {user.role}
        </div>
      </nav>
      <div className="backdrop" onClick={() => setNavOpen(false)} aria-hidden="true" />

      <main id="main" ref={mainRef} tabIndex={-1} className="app-main">
        {sessionState === 'unverifiable' && (
          <div className="session-banner" role="status">
            <WarningCircle size={18} aria-hidden="true" />
            No se puede verificar tu sesión, reintentando. Los datos en pantalla pueden estar desactualizados.
          </div>
        )}
        {children}
      </main>
    </div>
  )
}
