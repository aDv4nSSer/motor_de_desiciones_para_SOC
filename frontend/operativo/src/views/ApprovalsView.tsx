import { useState } from 'react'
import { CheckCircle, Prohibit, XCircle } from '@phosphor-icons/react'
import { resolveApproval } from '../api/approvals'
import { apiFetch } from '../api/client'
import type { Approval, ApprovalsPage } from '../api/types'
import { useAuth } from '../auth/AuthContext'
import { EmptyState, ErrorNotice, Freshness, LevelBadge, TableSkeleton, TierBadge } from '../components/common'
import { formatScore, formatTime, requiredLevel, roleReaches, shortId } from '../lib/format'
import { usePolling } from '../lib/usePolling'

type Decision = 'approved' | 'rejected'

const PAGE = 50
const FETCH_LIMIT = 1000 // tope del endpoint; hoy la cola real ronda las 260

interface RowState {
  confirming: Decision | null
  submitting: boolean
  message: { tone: 'danger' | 'info'; text: string } | null
}

interface Resolved {
  approval: Approval
  by: string
}

export function ApprovalsView() {
  const { user } = useAuth()
  const poll = usePolling(() => apiFetch<ApprovalsPage>(`/api/v1/dashboard/approvals?limit=${FETCH_LIMIT}`))
  const [rowState, setRowState] = useState<Record<string, RowState>>({})
  const [removed, setRemoved] = useState<Set<string>>(new Set())
  const [resolved, setResolved] = useState<Resolved[]>([])
  const [visible, setVisible] = useState(PAGE)

  if (!user) return null
  const role = user.role

  const page = poll.data
  const pending = (page?.items ?? []).filter((a) => a.status === 'pending' && !removed.has(a.trace_id))
  // Total real de la cola (no el largo de la página), descontando lo resuelto en esta sesión.
  const resolvedHere = (page?.items ?? []).filter((a) => removed.has(a.trace_id)).length
  const total = page ? Math.max(page.total - resolvedHere, pending.length) : 0
  const truncated = page ? page.total > page.items.length : false
  const state = (id: string): RowState => rowState[id] ?? { confirming: null, submitting: false, message: null }
  const patch = (id: string, p: Partial<RowState>) =>
    setRowState((prev) => ({ ...prev, [id]: { ...state(id), ...p } }))

  async function submit(a: Approval, decision: Decision) {
    patch(a.trace_id, { submitting: true, message: null })
    const outcome = await resolveApproval(a.trace_id, decision, role, a.approval_level)
    if (outcome.kind === 'done') {
      // Recién con el 200 del servidor sale de la lista de pendientes.
      setRemoved((prev) => new Set(prev).add(a.trace_id))
      setResolved((prev) => [{ approval: outcome.approval, by: user!.username }, ...prev])
      patch(a.trace_id, { submitting: false, confirming: null })
      return
    }
    patch(a.trace_id, {
      submitting: false,
      confirming: null,
      message: { tone: outcome.kind === 'conflict' || outcome.kind === 'gone' ? 'info' : 'danger', text: outcome.message },
    })
    if (outcome.kind === 'conflict' || outcome.kind === 'gone') void poll.refresh()
  }

  return (
    <section aria-labelledby="approvals-title">
      <header className="view-header">
        <h2 id="approvals-title">
          Aprobaciones pendientes{page?.available ? ` (${total})` : ''}
        </h2>
        <Freshness
          updatedAt={poll.updatedAt} paused={poll.paused}
          onTogglePause={() => poll.setPaused(!poll.paused)} onRefresh={() => void poll.refresh()}
        />
      </header>
      <p className="muted view-intro">
        Aprobar ejecuta la acción en producción (bloqueo de la IP de origen). Cada aprobación exige el nivel que trae el registro; tu rol es <strong>{role}</strong>.
      </p>

      {poll.error && <ErrorNotice message={poll.error} />}
      {page && !page.available && (
        <ErrorNotice message="El motor no pudo leer la cola de aprobaciones. La lista puede estar incompleta: no la tomes como vacía." />
      )}
      {truncated && (
        <p className="notice notice-info" role="status">
          Se muestran las {page!.items.length} más recientes de {page!.total} pendientes.
        </p>
      )}

      {poll.loading && !poll.data ? (
        <TableSkeleton cols={7} />
      ) : pending.length === 0 && page?.available !== false ? (
        <EmptyState title="No hay aprobaciones pendientes">
          Las acciones de alto impacto que requieran confirmación humana aparecerán aquí.
        </EmptyState>
      ) : (
        <ul className="approval-list">
          {pending.slice(0, visible).map((a) => {
            const s = state(a.trace_id)
            const allowed = roleReaches(role, a.approval_level)
            const level = requiredLevel(a.approval_level)
            return (
              <li key={a.trace_id} className="approval">
                <div className="approval-main">
                  <div className="approval-head">
                    <TierBadge tier={a.tier} />
                    <span className="mono strong">{a.src_ip ?? 'IP sin dato'}</span>
                    <LevelBadge level={level} />
                  </div>
                  <p className="approval-reason">{a.reason || 'Sin motivo registrado'}</p>
                  <p className="muted small mono">
                    {formatTime(a.created_at)}, riesgo {formatScore(a.risk_score)}, trace {shortId(a.trace_id)}
                  </p>
                  {s.message && (
                    <p className={`notice notice-${s.message.tone}`} role={s.message.tone === 'danger' ? 'alert' : 'status'}>
                      {s.message.text}
                    </p>
                  )}
                </div>

                <div className="approval-actions">
                  {!allowed ? (
                    <p className="muted small">Requiere rol {level} o superior.</p>
                  ) : s.confirming ? (
                    <div className="confirm" role="group" aria-label="Confirmar resolución">
                      <p className="small">
                        {s.confirming === 'approved'
                          ? <>¿Bloquear <span className="mono">{a.src_ip ?? 'esta IP'}</span> ahora?</>
                          : '¿Rechazar sin ejecutar ninguna acción?'}
                      </p>
                      <button
                        type="button"
                        className={`btn ${s.confirming === 'approved' ? 'btn-danger' : 'btn-secondary'}`}
                        disabled={s.submitting}
                        onClick={() => void submit(a, s.confirming!)}
                      >
                        {s.submitting ? 'Enviando…' : s.confirming === 'approved' ? 'Confirmar bloqueo' : 'Confirmar rechazo'}
                      </button>
                      <button type="button" className="btn btn-ghost" disabled={s.submitting} onClick={() => patch(a.trace_id, { confirming: null })}>
                        Cancelar
                      </button>
                    </div>
                  ) : (
                    <>
                      <button type="button" className="btn btn-primary" onClick={() => patch(a.trace_id, { confirming: 'approved', message: null })}>
                        <CheckCircle size={18} aria-hidden="true" /> Aprobar
                      </button>
                      <button type="button" className="btn btn-secondary" onClick={() => patch(a.trace_id, { confirming: 'rejected', message: null })}>
                        <Prohibit size={18} aria-hidden="true" /> Rechazar
                      </button>
                    </>
                  )}
                </div>
              </li>
            )
          })}
        </ul>
      )}

      {pending.length > visible && (
        <div className="list-footer">
          <button type="button" className="btn btn-secondary" onClick={() => setVisible((v) => v + PAGE)}>
            Mostrar {Math.min(PAGE, pending.length - visible)} más de {pending.length - visible} restantes
          </button>
        </div>
      )}

      {resolved.length > 0 && (
        <section className="resolved" aria-labelledby="resolved-title">
          <h3 id="resolved-title">Resueltas en esta sesión</h3>
          <ul>
            {resolved.map(({ approval: r }) => (
              <li key={r.trace_id}>
                {r.status === 'approved'
                  ? <CheckCircle size={16} aria-hidden="true" />
                  : <XCircle size={16} aria-hidden="true" />}
                <span className="mono">{r.src_ip ?? 'IP sin dato'}</span>
                <span>{r.status === 'approved' ? 'Aprobada' : 'Rechazada'} por {r.resolved_by ?? 'ti'}, {formatTime(r.resolved_at)}</span>
                {r.status === 'approved' && (
                  <span className={r.enforced ? 'text-ok' : 'text-danger'}>
                    {r.enforced ? 'bloqueo ejecutado' : 'bloqueo NO ejecutado, revisar auditoría'}
                  </span>
                )}
              </li>
            ))}
          </ul>
        </section>
      )}
    </section>
  )
}
