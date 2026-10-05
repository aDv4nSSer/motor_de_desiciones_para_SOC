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

/** Registro R1/R2 del worker (soc:response:audit / soc-responses-*). El stream
 *  también lleva eventos de acceso y aprobaciones manuales: solo las que traen
 *  accion_recomendada o enrichment son respuestas R1/R2. */
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

/** POST /api/v1/dashboard/responses/lookup (dashboard.lookup_responses, H49). */
export interface ResponseLookup {
  responses: Record<string, ResponseRecord>
  /** true: un trace_id ausente de `responses` de verdad no tiene registro. */
  complete: boolean
  sources: { opensearch: boolean; redis: boolean }
  /** Última tarea entregada al response-worker (ISO); null si no se pudo leer. */
  worker_frontier: string | null
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

// ── H43: vistas nuevas (motor/system_status.py, audit_view.py, user_admin.py,
// compliance.py) ─────────────────────────────────────────────────────────────

export type ComponentStatus = 'ok' | 'degraded' | 'down' | 'unknown' | 'not_configured'

export interface WazuhAgent {
  id: string
  name: string
  ip?: string | null
  status: string
  version?: string | null
  last_keepalive?: string | null
}

export interface NodeComponent {
  id: string
  name: string
  host: string
  status: ComponentStatus
  detail: string
  latency_ms: number | null
  metrics: Record<string, unknown> & { agents?: WazuhAgent[] }
}

export interface NodeStatus {
  generated_at: string
  overall: ComponentStatus
  components: NodeComponent[]
  metrics_endpoint: { available: boolean; detail: string }
}

export interface DocVerification {
  content_ok: boolean
  prev_link_ok: boolean | null
  next_link_ok: boolean | null
  chain_seq: number | null
  hash?: string | null
  prev_hash?: string | null
  note?: string
}

export interface TraceResult {
  trace_id: string
  available: boolean
  scope: 'full' | 'partial'
  decisions: { chain: string; doc: Record<string, unknown>; verification: DocVerification }[]
  events: { doc: Record<string, unknown>; verification: DocVerification }[]
  hidden_events: number
}

export interface ChainTail {
  pattern: string
  available: boolean
  verified: number
  from_seq: number | null
  to_seq: number | null
  first_seq?: number | null
  ok: boolean | null
  problems: string[]
  head_hash: string | null
  head_time: string | null
  duration_ms?: number
  cutover: {
    legacy_index?: string
    legacy_doc_count?: number
    legacy_head_hash?: string
    cutover_at?: string
    method?: string
    prev_hash?: string
  } | null
}

export interface ChainStatus {
  verified_at: string
  tail_size: number
  chains: { responses: ChainTail; decisions: ChainTail }
  full_verification: string
}

export interface AccessEvent {
  event_time: string | null
  username: string | null
  access_event: string | null
  detail: Record<string, unknown>
  chain_seq: number | null
  hash: string | null
}

export interface Account {
  username: string
  role: Role
  created_at: string
  disabled: boolean
  active_sessions: number
  manageable: boolean
  is_self: boolean
}

export interface SessionInfo {
  jti: string
  username: string
  role: Role
  issued_at: number
  expires_at: number
  user_agent: string
  client_ip: string
  is_self: boolean
  is_current: boolean
}

export type ChecklistStatus = 'cumple' | 'parcial' | 'no_cubierto' | 'fuera_de_alcance'

export interface ChecklistItem {
  id: string
  article: string
  title: string
  status: ChecklistStatus
  evidence: string
  source: string
}

export interface ComplianceReport {
  window_minutes: number
  generated_at: string
  fatiga_alertas_pct: number | null
  latencia_avg_ms: number | null
  latencia_p95_ms: number | null
  precision_bloqueos: {
    available: boolean
    total_blocks?: number
    corroborated?: { count: number; high_score_count: number; precision_pct: number | null; threshold: number }
    uncorroborated?: { count: number }
  }
  decisiones: { available: boolean; total: number; por_tier: Record<string, number> }
  respuestas: { available: boolean; acciones?: Record<string, number>; accesos?: Record<string, number>; cobertura_desde?: string | null }
  aprobaciones_pendientes: number | null
  usuarios_por_rol: Record<Role, number>
  sesiones_activas: number
  response_mode: string
  cadenas: ChainStatus
  checklist: ChecklistItem[]
  mttr_humano: { available: boolean; detail: string }
  nota_legal: string
  exportacion_pdf: { available: boolean; detail: string }
}

export interface TierBucket {
  start: string
  excluded: boolean
  counts: Record<'T0' | 'T1' | 'T2' | 'T3', number> | null
}

export interface ActionBucket {
  start: string
  ejecutadas: number
  derivadas_aprobacion: number
  expiradas: number
  rechazadas: number
}

export interface Trends {
  days: number
  interval: string
  generated_at: string
  excluded_range: { from: string; to: string; reason: string }
  tiers: { available: boolean; buckets: TierBucket[] }
  actions: { available: boolean; buckets: ActionBucket[] }
  pending_now: number | null
  corroboration: {
    available: boolean
    sources?: { source: string; count: number }[]
    evaluated?: number
    sin_corroboracion?: number
    crowdsec_observado?: number
    coverage_from?: string | null
    truncated?: boolean
  }
}
