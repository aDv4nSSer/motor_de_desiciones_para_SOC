// Shapes reales del backend (motor/main.py, motor/dashboard.py,
// motor/response/schemas.py, motor/response/approvals.py) al 2026-09-30.

export type Role = 'N1' | 'N2' | 'CISO'

export const ROLE_LEVEL: Record<Role, number> = { N1: 1, N2: 2, CISO: 3 }

export interface Me {
  username: string
  role: Role
}

export interface LoginResponse {
  access_token: string
  token_type: string
  role: Role
}

/** Documento de soc-decisions (GET /api/v1/dashboard/decisions). */
export interface Decision {
  trace_id: string
  timestamp: string
  tier: number
  tier_name: string
  risk_score: number
  ml_score?: number
  anomaly_score?: number
  decision: string
  L4_DST_PORT?: number
  OUT_PKTS?: number
  DURATION_MS?: number
  latency_ms?: number
  model_version?: string
}

export interface Enrichment {
  src_ip?: string | null
  reverse_dns?: string | null
  abuseipdb_score?: number | null
  abuseipdb_total_reports?: number | null
  abuseipdb_country?: string | null
  abuseipdb_available?: boolean
  otx_pulse_count?: number | null
  otx_available?: boolean
  corroborating_sources?: string[]
  corroboration_count?: number
  crowdsec_observado?: boolean
  crowdsec_scenario?: string | null
  notes?: string[]
}

export interface BlockResult {
  action?: string
  enforced?: boolean
  reason?: string
  requires_approval?: boolean
  approval_level?: string
}

/** Entrada de soc:response:audit (GET /api/v1/dashboard/blocks/recent).
 *  El stream también lleva eventos de acceso y aprobaciones manuales: solo
 *  las que traen accion_recomendada o enrichment son respuestas R1/R2. */
export interface ResponseRecord {
  trace_id?: string
  tier?: number
  risk_score?: number
  src_ip?: string | null
  dst_port?: number
  enrichment?: Enrichment
  block?: BlockResult
  accion_recomendada?: string
  case_id?: string | null
  access_event?: string
  manual_approval?: boolean
}

export interface Approval {
  trace_id: string
  src_ip: string | null
  tier: number
  risk_score: number
  reason: string
  approval_level: string
  status: 'pending' | 'approved' | 'rejected'
  created_at: string
  resolved_by: string | null
  resolved_at: string | null
  enforced?: boolean
  /** Eventos de la misma IP agrupados en esta aprobación (dedup por IP). */
  occurrences?: number
  last_seen_at?: string
  last_trace_id?: string
  /** IP de infraestructura propia: el servidor rechaza aprobarla (422). */
  safelisted?: boolean
}

/** GET /api/v1/dashboard/approvals: página + total real de la cola. */
export interface ApprovalsPage {
  items: Approval[]
  total: number
  limit: number
  available: boolean
}

export interface Stats {
  available: boolean
  window_minutes: number
  total_decisiones?: number
  por_tier?: Record<string, number>
}
