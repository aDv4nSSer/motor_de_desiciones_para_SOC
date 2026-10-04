import { useEffect, useId, useRef, useState } from 'react'
import type { ReactNode } from 'react'

// Gráficos SVG escritos a mano (sin librería): pocas formas, mismas reglas de
// marca para todos (skill dataviz): barras de hasta 24px con extremo de datos
// redondeado y base recta, 2px de separación entre segmentos, grilla de 1px
// recesiva, texto siempre en tinta (nunca en el color de la serie), tooltip
// por hover y por foco de teclado, y una tabla con los mismos valores.

export interface Series {
  key: string
  label: string
  color: string
}

const BAR_MAX = 24
const GAP = 2
const RADIUS = 4

function useWidth<T extends HTMLElement>(fallback = 640): [React.RefObject<T | null>, number] {
  const ref = useRef<T>(null)
  const [width, setWidth] = useState(fallback)
  useEffect(() => {
    const el = ref.current
    if (!el || typeof ResizeObserver === 'undefined') return
    const ro = new ResizeObserver(([entry]) => setWidth(Math.max(240, Math.floor(entry.contentRect.width))))
    ro.observe(el)
    return () => ro.disconnect()
  }, [])
  return [ref, width]
}

/** Columna con extremo superior redondeado y base recta. */
function topRoundedRect(x: number, y: number, w: number, h: number, r = RADIUS): string {
  if (h <= 0) return ''
  const rr = Math.min(r, w / 2, h)
  return `M${x},${y + h}V${y + rr}Q${x},${y} ${x + rr},${y}H${x + w - rr}Q${x + w},${y} ${x + w},${y + rr}V${y + h}Z`
}

/** Barra horizontal con extremo derecho redondeado y base izquierda recta. */
function rightRoundedRect(x: number, y: number, w: number, h: number, r = RADIUS): string {
  if (w <= 0) return ''
  const rr = Math.min(r, h / 2, w)
  return `M${x},${y}H${x + w - rr}Q${x + w},${y} ${x + w},${y + rr}V${y + h - rr}Q${x + w},${y + h} ${x + w - rr},${y + h}H${x}Z`
}

function niceMax(v: number): number {
  if (v <= 0) return 1
  const p = 10 ** Math.floor(Math.log10(v))
  const n = v / p
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * p
}

const fmt = (n: number) => n.toLocaleString('es-CL')

interface Tip { x: number; y: number; content: ReactNode }

function Tooltip({ tip }: { tip: Tip | null }) {
  if (!tip) return null
  return <div className="chart-tooltip" role="status" style={{ left: tip.x, top: tip.y }}>{tip.content}</div>
}

function Hatch({ id }: { id: string }) {
  return (
    <defs>
      <pattern id={id} width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
        <rect width="6" height="6" style={{ fill: 'var(--surface-2)' }} />
        <line x1="0" y1="0" x2="0" y2="6" style={{ stroke: 'var(--border-strong)', strokeWidth: 2 }} />
      </pattern>
    </defs>
  )
}

export interface Bucket<T> {
  label: string
  /** Etiqueta larga para tooltip y tabla. */
  title: string
  excluded?: boolean
  values: T
}

/** Una fila de columnas de una sola serie (para small multiples): escala
 *  propia, para que una serie chica no desaparezca al lado de una grande. */
export function ColumnRow({ buckets, color, seriesLabel, height = 64, showAxis = false, excludedNote }: {
  buckets: Bucket<number | null>[]
  color: string
  seriesLabel: string
  height?: number
  showAxis?: boolean
  excludedNote?: string
}) {
  const [ref, width] = useWidth<HTMLDivElement>()
  const [tip, setTip] = useState<Tip | null>(null)
  const hatchId = `hatch-${useId().replace(/[^A-Za-z0-9_-]/g, '')}`
  const axisH = showAxis ? 18 : 0
  const top = 8 // aire para el tick superior
  const left = 52
  const plotW = width - left - 4
  const band = plotW / Math.max(1, buckets.length)
  const barW = Math.max(2, Math.min(BAR_MAX, band - GAP * 2))
  const max = niceMax(Math.max(0, ...buckets.map((b) => b.values ?? 0)))
  const y = (v: number) => height - (v / max) * (height - top)
  const labelEvery = Math.ceil(buckets.length / Math.max(1, Math.floor(plotW / 56)))

  const show = (i: number) => {
    const b = buckets[i]
    setTip({
      x: Math.min(left + band * i + band / 2, width - 170), y: 0,
      content: <>
        <div className="tt-title">{b.title}</div>
        <div className="tt-row"><span>{seriesLabel}</span>
          <strong className="mono">{b.excluded ? 'sin dato' : fmt(b.values ?? 0)}</strong></div>
        {b.excluded && excludedNote && <div className="muted">{excludedNote}</div>}
      </>,
    })
  }

  return (
    <div className="chart" ref={ref} onMouseLeave={() => setTip(null)}>
      <svg width={width} height={height + axisH} role="img" aria-label={`${seriesLabel}: máximo ${fmt(Math.max(0, ...buckets.map((b) => b.values ?? 0)))} por intervalo`}>
        <Hatch id={hatchId} />
        <line className="gridline" x1={left} x2={width} y1={y(max)} y2={y(max)} />
        <text className="tick" x={left - 6} y={y(max) + 4} textAnchor="end">{fmt(max)}</text>
        <text className="tick" x={left - 6} y={height} textAnchor="end">0</text>
        {buckets.map((b, i) => {
          const cx = left + band * i + band / 2
          if (b.excluded) {
            return <rect key={b.title} x={left + band * i + GAP / 2} y={top} width={band - GAP} height={height - top} style={{ fill: `url(#${hatchId})` }} />
          }
          const v = b.values ?? 0
          return <path key={b.title} d={topRoundedRect(cx - barW / 2, y(v), barW, height - y(v))} style={{ fill: color }} />
        })}
        <line className="baseline" x1={left} x2={width} y1={height} y2={height} />
        {buckets.map((b, i) => (
          <rect
            key={`hit-${b.title}`} className="hit" x={left + band * i} y={0} width={band} height={height}
            tabIndex={0} aria-label={`${b.title}: ${b.excluded ? 'sin dato' : fmt(b.values ?? 0)}`}
            onMouseEnter={() => show(i)} onFocus={() => show(i)} onBlur={() => setTip(null)}
          />
        ))}
        {showAxis && buckets.map((b, i) => (i % labelEvery === 0) && (
          <text key={`x-${b.title}`} className="tick" x={left + band * i + band / 2} y={height + 14} textAnchor="middle">{b.label}</text>
        ))}
      </svg>
      <Tooltip tip={tip} />
    </div>
  )
}

/** Columnas apiladas (una escala, varias series) con leyenda y tooltip de
 *  todas las series del intervalo. */
export function StackedColumns({ buckets, series, height = 200 }: {
  buckets: Bucket<Record<string, number>>[]
  series: Series[]
  height?: number
}) {
  const [ref, width] = useWidth<HTMLDivElement>()
  const [tip, setTip] = useState<Tip | null>(null)
  const left = 44
  const axisH = 18
  const plotW = width - left - 4
  const band = plotW / Math.max(1, buckets.length)
  const barW = Math.max(2, Math.min(BAR_MAX, band - GAP * 2))
  const totals = buckets.map((b) => series.reduce((acc, s) => acc + (b.values[s.key] ?? 0), 0))
  const max = niceMax(Math.max(0, ...totals))
  const scale = (v: number) => (v / max) * (height - 8)
  const ticks = [0, max / 2, max]
  const labelEvery = Math.ceil(buckets.length / Math.max(1, Math.floor(plotW / 56)))

  const show = (i: number) => {
    const b = buckets[i]
    setTip({
      x: Math.min(left + band * i + band / 2, width - 190), y: 0,
      content: <>
        <div className="tt-title">{b.title}</div>
        {series.map((s) => (
          <div className="tt-row" key={s.key}>
            <span><span className="swatch" style={{ background: s.color }} /> {s.label}</span>
            <strong className="mono">{fmt(b.values[s.key] ?? 0)}</strong>
          </div>
        ))}
      </>,
    })
  }

  return (
    <div className="chart" ref={ref} onMouseLeave={() => setTip(null)}>
      <div className="legend-row" aria-hidden="true">
        {series.map((s) => <span key={s.key}><span className="swatch" style={{ background: s.color }} /> {s.label}</span>)}
      </div>
      <svg width={width} height={height + axisH} role="img" aria-label={`Columnas apiladas: ${series.map((s) => s.label).join(', ')}`}>
        {ticks.map((t) => (
          <g key={t}>
            <line className={t === 0 ? 'baseline' : 'gridline'} x1={left} x2={width} y1={height - scale(t)} y2={height - scale(t)} />
            <text className="tick" x={left - 6} y={height - scale(t) + 4} textAnchor="end">{fmt(Math.round(t))}</text>
          </g>
        ))}
        {buckets.map((b, i) => {
          const cx = left + band * i + band / 2
          let base = height
          const visible = series.filter((s) => (b.values[s.key] ?? 0) > 0)
          return (
            <g key={b.title}>
              {visible.map((s, j) => {
                const h = scale(b.values[s.key] ?? 0)
                const top = base - h
                const isTop = j === visible.length - 1
                // 2px de superficie entre segmentos: cada uno bajo el tope arranca GAP más abajo.
                const d = isTop
                  ? topRoundedRect(cx - barW / 2, top, barW, h)
                  : `M${cx - barW / 2},${top + GAP}H${cx + barW / 2}V${base}H${cx - barW / 2}Z`
                base = top
                return <path key={s.key} d={d} style={{ fill: s.color }} />
              })}
            </g>
          )
        })}
        {buckets.map((b, i) => (
          <rect
            key={`hit-${b.title}`} className="hit" x={left + band * i} y={0} width={band} height={height}
            tabIndex={0} aria-label={`${b.title}: ${series.map((s) => `${s.label} ${fmt(b.values[s.key] ?? 0)}`).join(', ')}`}
            onMouseEnter={() => show(i)} onFocus={() => show(i)} onBlur={() => setTip(null)}
          />
        ))}
        {buckets.map((b, i) => (i % labelEvery === 0) && (
          <text key={`x-${b.title}`} className="tick" x={left + band * i + band / 2} y={height + 14} textAnchor="middle">{b.label}</text>
        ))}
      </svg>
      <Tooltip tip={tip} />
    </div>
  )
}

/** Barras horizontales de una serie, valor en la punta. */
export function HBarList({ items, color, rowH = 28 }: {
  items: { label: string; value: number }[]
  color: string
  rowH?: number
}) {
  const [ref, width] = useWidth<HTMLDivElement>()
  const labelW = Math.min(160, width * 0.35)
  const valueW = 64
  const plotW = Math.max(40, width - labelW - valueW)
  const max = Math.max(1, ...items.map((i) => i.value))
  const barH = Math.min(BAR_MAX, rowH - 8)
  return (
    <div className="chart" ref={ref}>
      <svg width={width} height={items.length * rowH} role="img"
           aria-label={items.map((i) => `${i.label} ${fmt(i.value)}`).join(', ')}>
        <line className="baseline" x1={labelW} x2={labelW} y1={0} y2={items.length * rowH} />
        {items.map((it, i) => {
          const w = (it.value / max) * plotW
          const yTop = i * rowH + (rowH - barH) / 2
          return (
            <g key={it.label}>
              <text className="label" x={labelW - 8} y={yTop + barH / 2 + 4} textAnchor="end">{it.label}</text>
              <path d={rightRoundedRect(labelW, yTop, w, barH)} style={{ fill: color }}>
                <title>{`${it.label}: ${fmt(it.value)}`}</title>
              </path>
              <text className="value" x={labelW + w + 6} y={yTop + barH / 2 + 4}>{fmt(it.value)}</text>
            </g>
          )
        })}
      </svg>
    </div>
  )
}

/** Tabla con los mismos valores del gráfico (accesibilidad e impresión). */
export function TableView({ caption, columns, rows }: {
  caption: string
  columns: string[]
  rows: (string | number)[][]
}) {
  return (
    <details className="table-view">
      <summary>Ver como tabla</summary>
      <div className="table-wrap mt3">
        <table className="data">
          <caption className="sr-only">{caption}</caption>
          <thead><tr>{columns.map((c, i) => <th key={c} scope="col" className={i > 0 ? 'num' : undefined}>{c}</th>)}</tr></thead>
          <tbody>
            {rows.map((r) => (
              <tr key={String(r[0])}>{r.map((v, i) => <td key={i} className={i > 0 ? 'num mono' : 'mono'}>{typeof v === 'number' ? fmt(v) : v}</td>)}</tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  )
}
