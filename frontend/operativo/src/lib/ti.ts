import type { Enrichment } from '../api/types'

/** Estado de una fuente de TI en un registro de R1, separando la política
 *  (no se consultó a propósito) del error real (H60). Las notas son las que
 *  escribe motor/response/enrichment.py; el orden importa: "evento stale" y
 *  "negative cache" comparten el texto "no disponible". */
function sourceStatus(name: string, prefix: string, available: boolean | undefined, value: string | null,
  notes: string[] | undefined): string {
  if (value !== null) return `${name} ${value}`
  const note = (notes ?? []).find((n) => n.toLowerCase().startsWith(prefix)) ?? ''
  if (available !== false && !note) return `${name} sin dato`
  if (note.includes('IP no pública')) return `${name} no aplica (IP no pública)`
  if (note.includes('stale')) return `${name} no consultada (evento antiguo, solo caché)`
  if (note.includes('r2_min_tier') || note.includes('throttling') || note.includes('no decisiva')) {
    return `${name} no consultada (política de cuota, solo caché)`
  }
  if (note.includes('cuota diaria agotada')) return `${name} no consultada (cuota diaria agotada)`
  if (note.includes('no configurada')) return `${name} no configurada`
  if (!note) return `${name} sin dato del motivo`
  return `${name} no disponible (error)`
}

export function abuseipdbStatus(e: Enrichment): string {
  const v = typeof e.abuseipdb_score === 'number' ? String(e.abuseipdb_score) : null
  return sourceStatus('AbuseIPDB', 'abuseipdb', e.abuseipdb_available, v, e.notes)
}

export function otxStatus(e: Enrichment): string {
  const v = typeof e.otx_pulse_count === 'number'
    ? `${e.otx_pulse_count} ${e.otx_pulse_count === 1 ? 'pulso' : 'pulsos'}` : null
  return sourceStatus('OTX', 'otx', e.otx_available, v, e.notes)
}

/** "1 fuente corrobora", "2 fuentes corroboran". */
export function corroboranLabel(n: number | null | undefined): string {
  const k = n ?? 0
  return k === 1 ? '1 fuente corrobora' : `${k} fuentes corroboran`
}
