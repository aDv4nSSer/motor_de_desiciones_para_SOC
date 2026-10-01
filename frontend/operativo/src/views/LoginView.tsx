import { useState } from 'react'
import type { FormEvent } from 'react'
import { ShieldCheck, WarningCircle } from '@phosphor-icons/react'
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
      <form className="login-card" onSubmit={onSubmit} aria-describedby={error ? 'login-error' : undefined}>
        <div className="login-brand">
          <ShieldCheck size={28} weight="duotone" aria-hidden="true" />
          <div>
            <h1>R-SOAR</h1>
            <p className="muted">Consola operativa</p>
          </div>
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
            value={password} onChange={(e) => setPassword(e.target.value)}
          />
        </div>

        {error && (
          <p id="login-error" className="notice notice-danger" role="alert">
            <WarningCircle size={18} aria-hidden="true" /> {error}
          </p>
        )}

        <button type="submit" className="btn btn-primary btn-block" disabled={submitting}>
          {submitting ? 'Verificando…' : 'Iniciar sesión'}
        </button>
        <p className="muted small">La sesión se mantiene solo en esta pestaña y se cierra al recargar.</p>
      </form>
    </main>
  )
}
