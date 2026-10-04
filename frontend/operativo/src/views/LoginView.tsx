import { useState } from 'react'
import type { FormEvent } from 'react'
import { Fingerprint, LockKey, ShieldCheck, TreeStructure, WarningCircle } from '@phosphor-icons/react'
import uboLogo from '../assets/brand/ubo-logo-provisional.png'
import { useAuth } from '../auth/AuthContext'

export function LoginView() {
  const { login, logoutReason } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    setSubmitting(true)
    setError(null)
    const outcome = await login(username.trim(), password)
    setSubmitting(false)
    if (!outcome.ok) {
      setError(outcome.message)
      if (outcome.kind === 'credentials') setPassword('')
    }
  }

  return (
    <main className="login">
      <section className="login-brand-panel" aria-label="R-SOAR">
        <div className="login-product">
          <ShieldCheck size={26} weight="duotone" aria-hidden="true" /> R-SOAR
        </div>
        <div className="login-claim">
          <h1>Decisiones de respuesta basadas en riesgo, con evidencia auditable</h1>
          <p>Consola operativa y de gestión para el SOC: detección, aprobación humana y trazabilidad para la Ley 21.663.</p>
        </div>
        <ul className="login-facts">
          <li><TreeStructure size={18} aria-hidden="true" /> Motor de decisión con ML calibrado y orquestación de respuesta.</li>
          <li><Fingerprint size={18} aria-hidden="true" /> Cada decisión y cada acceso queda en una cadena de hashes verificable.</li>
          <li><LockKey size={18} aria-hidden="true" /> Acceso por rol: Operador N1, Operador N2 y CISO.</li>
        </ul>
      </section>

      <div className="login-form-panel">
        <form className="login-card" onSubmit={onSubmit} aria-describedby={error ? 'login-error' : undefined}>
          <span className="brand-plate">
            <img className="login-logo" src={uboLogo} alt="Universidad Bernardo O'Higgins" />
          </span>
          <div>
            <h2>Iniciar sesión</h2>
            <p className="muted small">Usa la cuenta que te asignó un Operador N2 o el CISO.</p>
          </div>

          {logoutReason && !error && (
            <p className="notice notice-info" role="status">{logoutReason}</p>
          )}

          <div className="field">
            <label htmlFor="username">Usuario</label>
            <input
              id="username" name="username" autoComplete="username" required autoFocus
              value={username} onChange={(e) => setUsername(e.target.value)}
            />
          </div>
          <div className="field">
            <label htmlFor="password">Contraseña</label>
            <input
              id="password" name="password" type="password" autoComplete="current-password" required
              aria-invalid={error !== null && password === ''}
              value={password} onChange={(e) => setPassword(e.target.value)}
            />
          </div>

          {error && (
            <p id="login-error" className="notice notice-danger" role="alert">
              <WarningCircle size={18} aria-hidden="true" /> {error}
            </p>
          )}

          <button type="submit" className="btn btn-primary btn-block btn-lg" disabled={submitting}>
            {submitting ? 'Verificando…' : 'Iniciar sesión'}
          </button>
          <p className="login-foot">La sesión se mantiene solo en esta pestaña y se cierra al recargar o al cerrar sesión.</p>
        </form>
      </div>
    </main>
  )
}
