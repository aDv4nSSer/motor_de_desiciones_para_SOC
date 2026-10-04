import {
  ArrowClockwise, CheckCircle, LockKey, MinusCircle, Pause, Play, Question, WarningCircle, XCircle,
} from '@phosphor-icons/react'
import type { Icon } from '@phosphor-icons/react'
import type { ReactNode } from 'react'
import type { ComponentStatus } from '../api/types'
import { formatTime } from '../lib/format'
import { TIER_LABEL } from '../lib/labels'

/** Severidad: paleta semántica propia (no la de marca) + texto siempre. */
export function TierBadge({ tier }: { tier: number }) {
  const t = Math.max(0, Math.min(3, tier))
  return <span className={`badge tier-${t}`}>{TIER_LABEL[t]}</span>
}

const STATUS: Record<ComponentStatus, { label: string; cls: string; icon: Icon }> = {
  ok: { label: 'Operativo', cls: 'st-ok', icon: CheckCircle },
  degraded: { label: 'Degradado', cls: 'st-warn', icon: WarningCircle },
  down: { label: 'Caído', cls: 'st-critical', icon: XCircle },
  unknown: { label: 'Sin dato', cls: 'st-neutral', icon: Question },
  not_configured: { label: 'No configurado', cls: 'st-neutral', icon: MinusCircle },
}

/** Estado de salud: ícono + texto + color (nunca solo color). */
export function StatusBadge({ status }: { status: ComponentStatus }) {
  const s = STATUS[status] ?? STATUS.unknown
  const IconCmp = s.icon
  return (
    <span className={`badge ${s.cls}`}>
      <IconCmp size={14} weight="fill" aria-hidden="true" /> {s.label}
    </span>
  )
}

/** Página para una ruta que el rol no puede abrir. La vista pedida no se
 *  monta (ni hace llamadas); el backend igual respondería 403. */
export function Forbidden({ needs }: { needs: string }) {
  return (
    <section aria-labelledby="forbidden-title">
      <div className="empty forbidden">
        <LockKey size={32} weight="duotone" aria-hidden="true" />
        <h2 id="forbidden-title" className="empty-title">Acceso restringido</h2>
        <p className="muted">Esta sección requiere rol {needs}. Si la necesitas, pídela a un Operador N2 o al CISO.</p>
      </div>
    </section>
  )
}


export function LevelBadge({ level }: { level: string }) {
  return <span className="badge badge-outline">Requiere {level}</span>
}

interface FreshnessProps {
  updatedAt: Date | null
  paused: boolean
  onTogglePause: () => void
  onRefresh: () => void
  children?: ReactNode
}

/** Cuándo se actualizó, y controles de pausa/refresco (telemetría "en vivo"
 *  solo con hora de actualización visible). */
export function Freshness({ updatedAt, paused, onTogglePause, onRefresh, children }: FreshnessProps) {
  return (
    <div className="freshness">
      <span className="muted small" aria-live="polite">
        {updatedAt ? `Actualizado ${formatTime(updatedAt.toISOString())}` : 'Cargando…'}
        {paused && ' (en pausa)'}
      </span>
      {children}
      <button type="button" className="btn btn-ghost btn-sm" onClick={onTogglePause}>
        {paused ? <Play size={16} aria-hidden="true" /> : <Pause size={16} aria-hidden="true" />}
        {paused ? 'Reanudar' : 'Pausar'}
      </button>
      <button type="button" className="btn btn-ghost btn-sm" onClick={onRefresh}>
        <ArrowClockwise size={16} aria-hidden="true" /> Actualizar
      </button>
    </div>
  )
}

export function ErrorNotice({ message }: { message: string }) {
  return (
    <p className="notice notice-danger" role="alert">
      <WarningCircle size={18} aria-hidden="true" /> {message}
    </p>
  )
}

/** Esqueleto con la forma de una tabla, mientras llega la primera carga. */
export function TableSkeleton({ rows = 6, cols = 6 }: { rows?: number; cols?: number }) {
  return (
    <div className="skeleton-table" aria-busy="true" aria-label="Cargando datos">
      {Array.from({ length: rows }, (_, r) => (
        <div className="skeleton-row" key={r}>
          {Array.from({ length: cols }, (_, c) => <span className="skeleton-cell" key={c} />)}
        </div>
      ))}
    </div>
  )
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <p className="empty-title">{title}</p>
      {children && <div className="muted">{children}</div>}
    </div>
  )
}
