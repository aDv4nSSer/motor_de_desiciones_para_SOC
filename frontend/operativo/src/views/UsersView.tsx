import { useState } from 'react'
import type { FormEvent } from 'react'
import { Key, Prohibit, SignOut, UserPlus, UserSwitch } from '@phosphor-icons/react'
import { ApiError, NetworkError, SessionRevokedError, apiFetch } from '../api/client'
import type { Account, Role, SessionInfo } from '../api/types'
import { useAuth } from '../auth/AuthContext'
import { EmptyState, ErrorNotice, Freshness, TableSkeleton } from '../components/common'
import { formatTime } from '../lib/format'
import { usePolling } from '../lib/usePolling'

const MIN_PASSWORD = 12 // mismo mínimo que motor/users.py y scripts/manage_users.py
const ROLE_NAME: Record<Role, string> = { N1: 'Operador N1', N2: 'Operador N2', CISO: 'CISO / Gerencia' }

interface UsersData {
  accounts: Account[]
  assignable: Role[]
  sessions: SessionInfo[]
}

async function fetchUsers(): Promise<UsersData> {
  const [users, sessions] = await Promise.all([
    apiFetch<{ items: Account[]; assignable_roles: Role[] }>('/api/v1/dashboard/users'),
    apiFetch<{ items: SessionInfo[] }>('/api/v1/dashboard/sessions'),
  ])
  return { accounts: users.items, assignable: users.assignable_roles, sessions: sessions.items }
}

type Msg = { tone: 'danger' | 'info'; text: string } | null

/** Ejecuta una acción de gestión y traduce el error real del servidor. */
async function run<T>(fn: () => Promise<T>): Promise<{ ok: true; value: T } | { ok: false; text: string }> {
  try {
    return { ok: true, value: await fn() }
  } catch (e) {
    if (e instanceof SessionRevokedError) throw e
    if (e instanceof NetworkError) return { ok: false, text: 'Sin conexión con el motor: no se sabe si el cambio se aplicó. Actualiza la lista.' }
    if (e instanceof ApiError) return { ok: false, text: e.detail || `El motor rechazó la operación (HTTP ${e.status}).` }
    return { ok: false, text: 'Error inesperado.' }
  }
}

function shortAgent(ua: string): string {
  if (!ua) return 'sin dato'
  const m = ua.match(/(Firefox|Edg|Chrome|Safari)\/[\d.]+/)
  const os = ua.match(/\(([^;)]+)/)?.[1]
  return [m?.[0].replace('Edg', 'Edge'), os].filter(Boolean).join(', ') || ua.slice(0, 40)
}

function CreateUser({ assignable, onDone }: { assignable: Role[]; onDone: (msg: Msg) => void }) {
  const [username, setUsername] = useState('')
  const [role, setRole] = useState<Role>(assignable[0] ?? 'N1')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const mismatch = confirm !== '' && confirm !== password
  const short = password !== '' && password.length < MIN_PASSWORD

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    if (mismatch || short) return
    setSubmitting(true)
    setError(null)
    const r = await run(() => apiFetch('/api/v1/dashboard/users', {
      method: 'POST', body: JSON.stringify({ username: username.trim(), password, role }),
    }))
    setSubmitting(false)
    if (!r.ok) { setError(r.text); return }
    setUsername(''); setPassword(''); setConfirm('')
    onDone({ tone: 'info', text: `Usuario ${username.trim()} creado con rol ${role}.` })
  }

  return (
    <form className="panel panel-body" onSubmit={onSubmit} aria-labelledby="create-title">
      <h3 id="create-title" className="mb2">Alta de usuario</h3>
      <div className="form-grid">
        <div className="field">
          <label htmlFor="nu-username">Usuario</label>
          <input id="nu-username" required minLength={3} maxLength={32} pattern="[a-z0-9][a-z0-9._\-]{2,31}"
                 autoComplete="off" value={username} onChange={(e) => setUsername(e.target.value)}
                 aria-describedby="nu-username-hint" />
          <span id="nu-username-hint" className="hint">Minúsculas, números, punto o guion.</span>
        </div>
        <div className="field">
          <label htmlFor="nu-role">Rol</label>
          <select id="nu-role" value={role} onChange={(e) => setRole(e.target.value as Role)}>
            {assignable.map((r) => <option key={r} value={r}>{ROLE_NAME[r]}</option>)}
          </select>
          <span className="hint">{assignable.length === 1 ? 'Tu rol solo puede crear cuentas N1.' : 'Mínimo privilegio: asigna el rol justo.'}</span>
        </div>
        <div className="field">
          <label htmlFor="nu-pass">Contraseña inicial</label>
          <input id="nu-pass" type="password" required autoComplete="new-password" value={password}
                 onChange={(e) => setPassword(e.target.value)} aria-invalid={short} aria-describedby="nu-pass-hint" />
          <span id="nu-pass-hint" className="hint">{short ? `Faltan ${MIN_PASSWORD - password.length} caracteres.` : `Al menos ${MIN_PASSWORD} caracteres.`}</span>
        </div>
        <div className="field">
          <label htmlFor="nu-confirm">Confirmar contraseña</label>
          <input id="nu-confirm" type="password" required autoComplete="new-password" value={confirm}
                 onChange={(e) => setConfirm(e.target.value)} aria-invalid={mismatch} aria-describedby="nu-confirm-hint" />
          <span id="nu-confirm-hint" className="hint">{mismatch ? 'No coincide.' : 'Entrégala por un canal seguro.'}</span>
        </div>
      </div>
      {error && <ErrorNotice message={error} />}
      <div className="mt3">
        <button type="submit" className="btn btn-primary" disabled={submitting || mismatch || short}>
          <UserPlus size={18} aria-hidden="true" /> {submitting ? 'Creando…' : 'Crear usuario'}
        </button>
      </div>
    </form>
  )
}

type RowAction = { kind: 'disable' | 'revoke' | 'password' | 'role' } | null

function AccountRow({ a, assignable, onChanged }: { a: Account; assignable: Role[]; onChanged: (m: Msg) => void }) {
  const [action, setAction] = useState<RowAction>(null)
  const [busy, setBusy] = useState(false)
  const [newRole, setNewRole] = useState<Role>(a.role)
  const [password, setPassword] = useState('')
  const [msg, setMsg] = useState<Msg>(null)
  const path = `/api/v1/dashboard/users/${encodeURIComponent(a.username)}`

  async function exec<T>(fn: () => Promise<T>, done: (v: T) => string) {
    setBusy(true)
    setMsg(null)
    const r = await run(fn)
    setBusy(false)
    if (!r.ok) { setMsg({ tone: 'danger', text: r.text }); return }
    setAction(null)
    setPassword('')
    onChanged({ tone: 'info', text: done(r.value) })
  }

  const disable = () => exec(
    () => apiFetch<{ revoked_sessions: number }>(path, { method: 'PATCH', body: JSON.stringify({ disabled: !a.disabled }) }),
    (v) => a.disabled ? `${a.username} reactivado.` : `${a.username} dado de baja; ${v.revoked_sessions} sesiones revocadas.`,
  )
  const changeRole = () => exec(
    () => apiFetch<{ revoked_sessions: number }>(path, { method: 'PATCH', body: JSON.stringify({ role: newRole }) }),
    (v) => `${a.username} ahora es ${newRole}; ${v.revoked_sessions} sesiones revocadas (debe volver a entrar).`,
  )
  const resetPassword = () => exec(
    () => apiFetch<{ revoked_sessions: number }>(`${path}/password`, { method: 'POST', body: JSON.stringify({ password }) }),
    (v) => `Contraseña de ${a.username} restablecida; ${v.revoked_sessions} sesiones revocadas.`,
  )
  const revokeAll = () => exec(
    () => apiFetch<{ revoked: number }>(`${path}/sessions`, { method: 'DELETE' }),
    (v) => `${v.revoked} sesiones de ${a.username} revocadas.`,
  )

  return (
    <tr>
      <td className="mono">{a.username}{a.is_self && <span className="muted"> (tú)</span>}</td>
      <td>{ROLE_NAME[a.role]}</td>
      <td>{a.disabled ? <span className="badge st-neutral">De baja</span> : <span className="badge st-ok">Activo</span>}</td>
      <td className="mono">{formatTime(a.created_at)}</td>
      <td className="num mono">{a.active_sessions}</td>
      <td>
        {!a.manageable ? (
          <span className="muted small">{a.is_self ? 'Tu cuenta' : 'Fuera de tu alcance'}</span>
        ) : action === null ? (
          <div className="row-actions">
            {!a.disabled && assignable.length > 1 && (
              <button type="button" className="btn btn-ghost btn-sm" onClick={() => setAction({ kind: 'role' })}>
                <UserSwitch size={16} aria-hidden="true" /> Rol
              </button>
            )}
            <button type="button" className="btn btn-ghost btn-sm" onClick={() => setAction({ kind: 'password' })}>
              <Key size={16} aria-hidden="true" /> Contraseña
            </button>
            {a.active_sessions > 0 && (
              <button type="button" className="btn btn-ghost btn-sm" onClick={() => setAction({ kind: 'revoke' })}>
                <SignOut size={16} aria-hidden="true" /> Revocar sesiones
              </button>
            )}
            <button type="button" className="btn btn-secondary btn-sm" onClick={a.disabled ? disable : () => setAction({ kind: 'disable' })}>
              <Prohibit size={16} aria-hidden="true" /> {a.disabled ? 'Reactivar' : 'Dar de baja'}
            </button>
          </div>
        ) : (
          <div className="confirm" role="group" aria-label={`Acción sobre ${a.username}`}>
            {action.kind === 'disable' && <p className="small">¿Dar de baja a <span className="mono">{a.username}</span>? Sus sesiones se cierran.</p>}
            {action.kind === 'revoke' && <p className="small">¿Cerrar las {a.active_sessions} sesiones de <span className="mono">{a.username}</span>?</p>}
            {action.kind === 'role' && (
              <>
                <label className="sr-only" htmlFor={`role-${a.username}`}>Nuevo rol</label>
                <select id={`role-${a.username}`} className="select" value={newRole} onChange={(e) => setNewRole(e.target.value as Role)}>
                  {assignable.map((r) => <option key={r} value={r}>{ROLE_NAME[r]}</option>)}
                </select>
              </>
            )}
            {action.kind === 'password' && (
              <>
                <label className="sr-only" htmlFor={`pw-${a.username}`}>Nueva contraseña</label>
                <input id={`pw-${a.username}`} className="input" type="password" autoComplete="new-password"
                       placeholder={`Mínimo ${MIN_PASSWORD} caracteres`} value={password} onChange={(e) => setPassword(e.target.value)} />
              </>
            )}
            <button
              type="button" disabled={busy || (action.kind === 'password' && password.length < MIN_PASSWORD) || (action.kind === 'role' && newRole === a.role)}
              className={`btn btn-sm ${action.kind === 'disable' ? 'btn-danger' : 'btn-primary'}`}
              onClick={() => void (action.kind === 'disable' ? disable() : action.kind === 'revoke' ? revokeAll()
                : action.kind === 'role' ? changeRole() : resetPassword())}
            >
              {busy ? 'Aplicando…' : 'Confirmar'}
            </button>
            <button type="button" className="btn btn-ghost btn-sm" disabled={busy} onClick={() => { setAction(null); setMsg(null) }}>Cancelar</button>
          </div>
        )}
        {msg && <p className={`notice notice-${msg.tone}`} role="alert">{msg.text}</p>}
      </td>
    </tr>
  )
}

function SessionsTable({ sessions, onChanged }: { sessions: SessionInfo[]; onChanged: (m: Msg) => void }) {
  const { logout } = useAuth()
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function revoke(s: SessionInfo) {
    setBusy(s.jti)
    setError(null)
    const r = await run(() => apiFetch<{ own_session_revoked: boolean }>(
      `/api/v1/dashboard/sessions/${encodeURIComponent(s.username)}/${encodeURIComponent(s.jti)}`, { method: 'DELETE' }))
    setBusy(null)
    if (!r.ok) { setError(r.text); return }
    if (r.value.own_session_revoked) { logout(); return }
    onChanged({ tone: 'info', text: `Sesión de ${s.username} revocada: ese token deja de servir desde ya.` })
  }

  if (sessions.length === 0) return <EmptyState title="No hay sesiones activas visibles para tu rol" />
  return (
    <>
      {error && <ErrorNotice message={error} />}
      <div className="table-wrap">
        <table className="data">
          <thead>
            <tr>
              <th scope="col">Usuario</th><th scope="col">Rol</th><th scope="col">Inicio</th><th scope="col">Expira</th>
              <th scope="col">Cliente</th><th scope="col">IP informada</th><th scope="col"><span className="sr-only">Acciones</span></th>
            </tr>
          </thead>
          <tbody>
            {sessions.map((s) => (
              <tr key={s.jti}>
                <td className="mono">{s.username}{s.is_current && <span className="badge badge-brand ml1">Esta sesión</span>}</td>
                <td>{s.role}</td>
                <td className="mono">{formatTime(new Date(s.issued_at * 1000).toISOString())}</td>
                <td className="mono">{formatTime(new Date(s.expires_at * 1000).toISOString())}</td>
                <td className="small" title={s.user_agent}>{shortAgent(s.user_agent)}</td>
                <td className="mono">{s.client_ip || 'sin dato'}</td>
                <td>
                  <button type="button" className="btn btn-secondary btn-sm" disabled={busy === s.jti} onClick={() => void revoke(s)}>
                    <SignOut size={16} aria-hidden="true" /> {s.is_current ? 'Cerrar esta sesión' : 'Revocar'}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}

export function UsersView() {
  const { user } = useAuth()
  const poll = usePolling(fetchUsers)
  const [msg, setMsg] = useState<Msg>(null)
  if (!user) return null
  const data = poll.data

  const changed = (m: Msg) => {
    setMsg(m)
    void poll.refresh()
  }

  return (
    <section aria-labelledby="users-title">
      <header className="view-header">
        <h2 id="users-title">Usuarios y sesiones</h2>
        <Freshness
          updatedAt={poll.updatedAt} paused={poll.paused}
          onTogglePause={() => poll.setPaused(!poll.paused)} onRefresh={() => void poll.refresh()}
        />
      </header>
      <p className="view-intro">
        {user.role === 'CISO'
          ? 'Como CISO gestionas todas las cuentas. El sistema no permite quedar sin un CISO habilitado.'
          : 'Como Operador N2 gestionas solo cuentas N1; las cuentas N2 y CISO las administra el CISO.'}
        {' '}Nadie cambia su propio rol ni se da de baja. Cada acción queda en la bitácora de auditoría.
      </p>

      {msg && <p className={`notice notice-${msg.tone}`} role="status">{msg.text}</p>}
      {poll.error && <ErrorNotice message={poll.error} />}

      {poll.loading && !data ? <TableSkeleton cols={6} /> : data && (
        <>
          <CreateUser assignable={data.assignable} onDone={changed} />

          <div className="section-title"><h3>Cuentas</h3></div>
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th scope="col">Usuario</th><th scope="col">Rol</th><th scope="col">Estado</th><th scope="col">Creado</th>
                  <th scope="col" className="num">Sesiones</th><th scope="col"><span className="sr-only">Acciones</span></th>
                </tr>
              </thead>
              <tbody>
                {data.accounts.map((a) => <AccountRow key={a.username} a={a} assignable={data.assignable} onChanged={changed} />)}
              </tbody>
            </table>
          </div>

          <div className="section-title"><h3>Sesiones activas</h3><span className="muted small">Revocar invalida ese token en la siguiente llamada.</span></div>
          <SessionsTable sessions={data.sessions} onChanged={changed} />
        </>
      )}
    </section>
  )
}
