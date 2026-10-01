import { ArrowClockwise, Pause, Play, WarningCircle } from '@phosphor-icons/react'
import type { ReactNode } from 'react'
import { formatTime } from '../lib/format'

/** Severidad: color + texto siempre (nunca solo color). */
export function TierBadge({ tier }: { tier: number }) {
  const label = tier >= 3 ? 'T3 crítico' : tier === 2 ? 'T2 medio' : tier === 1 ? 'T1 bajo' : 'T0'
  const cls = tier >= 3 ? 'sev-critical' : tier === 2 ? 'sev-high' : 'sev-low'
  return <span className={`badge ${cls}`}>{label}</span>
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
