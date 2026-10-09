import { describe, expect, it } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import App from '../App'
import { AuthProvider } from '../auth/AuthContext'
import { json, mockFetch } from './helpers'

const VALIDATION = { start: '2026-10-07T23:40:00+00:00', end: '2026-10-10T23:40:00+00:00' }

const CORR = {
  available: true, shadow: true, validation: VALIDATION, from: VALIDATION.start, clamped: true,
  t3_total: 27_406, scored: 3_839, excluded: 23_567, eligible: 3_775, eligible_pct: 98.3,
  bands: { high: 3_775, medium: 19, low: 0, ambiguous: 45 },
  groups: { evaluated: 3_839, available_pct: { ml: 100, ti: 99.8, signature: 0.7, context: 98.9 } },
}

function report(corroboracion_sombra: unknown, generated_at = '2026-10-08T12:00:00Z') {
  return {
    window_minutes: 1440, generated_at,
    fatiga_alertas_pct: 91.2, latencia_avg_ms: 12, latencia_p95_ms: 40,
    precision_bloqueos: { available: true, total_blocks: 0, corroborated: { count: 0, high_score_count: 0, precision_pct: null, threshold: 40 }, uncorroborated: { count: 0 } },
    corroboracion_sombra,
    decisiones: { available: true, total: 50_000, por_tier: { T3_CRITICO: 12_400, T2_MEDIO: 300 } },
    respuestas: { available: true, acciones: {}, accesos: {} },
    aprobaciones_pendientes: 0, usuarios_por_rol: { N1: 1, N2: 1, CISO: 1 }, sesiones_activas: 1,
    response_mode: 'enforce',
    cadenas: { verified_at: '2026-10-08T12:00:00Z', tail_size: 2000, chains: { responses: { ok: true }, decisions: { ok: true } } },
    checklist: [], mttr_humano: { available: false, detail: '' }, nota_legal: 'nota',
    exportacion_pdf: { available: false, detail: 'pendiente' },
  }
}

/** Entra como CISO: su vista por defecto es Cumplimiento (ventana 24 h). */
async function enterCompliance(corr: unknown, generatedAt?: string) {
  const mock = mockFetch({
    '/api/v1/auth/login': () => json(200, { access_token: 'tok', token_type: 'bearer', role: 'CISO' }),
    '/api/v1/dashboard/compliance': () => json(200, report(corr, generatedAt)),
  })
  const user = userEvent.setup()
  render(<AuthProvider><App /></AuthProvider>)
  await user.type(screen.getByLabelText('Usuario'), 'ana')
  await user.type(screen.getByLabelText('Contraseña'), 'una-clave-larga')
  await user.click(screen.getByRole('button', { name: 'Iniciar sesión' }))
  return mock
}

async function kpi(name: RegExp) {
  const metrics = await screen.findByLabelText('Métricas de valor')
  return within(metrics).getByText(name).closest('.kpi') as HTMLElement
}

describe('tarjeta de corroboración multi-fuente (Cumplimiento)', () => {
  it('reemplaza la de AbuseIPDB y muestra el % elegible sobre T3 con score, marcado como sombra', async () => {
    const { calls } = await enterCompliance(CORR)

    const card = await kpi(/Corroboración multi-fuente de T3/)
    expect(screen.queryByText(/Bloqueos corroborados por AbuseIPDB/)).not.toBeInTheDocument()
    expect(within(card).getByText('modo sombra')).toBeInTheDocument()
    expect(within(card).getByText('98,3 %')).toBeInTheDocument()
    expect(within(card).getByText(/3\.775 de 3\.839 T3 desde el inicio de la validación \(7 oct, 20:40\)/)).toBeInTheDocument()
    // La línea de sombra va aparte del número principal.
    const notice = within(card).getByText(/No determina bloqueos reales/)
    expect(notice).toHaveClass('kpi-shadow')
    expect(notice).toHaveTextContent('período de validación hasta el 10 oct, 20:40')
    // Misma ventana que el resto de la vista.
    expect(calls.find((c) => c.url.startsWith('/api/v1/dashboard/compliance'))?.url).toContain('window_minutes=1440')

    const panel = screen.getByRole('region', { name: /Corroboración multi-fuente de T3/ })
    expect(within(panel).getByText('Ambigua (grupos en desacuerdo)').nextSibling).toHaveTextContent('45 (1,2 %)')
    expect(within(panel).getByText('Firma Suricata (classtype, ATT&CK)').nextSibling).toHaveTextContent('0,7 %')
    expect(within(panel).getByText(/sobre 3\.839 T3 con detalle por grupo/)).toBeInTheDocument()
    // Las T3 sin score se informan aparte, nunca en el denominador del %.
    expect(within(panel).getByText(/Calculado desde el inicio del período de validación \(7 oct, 20:40\)/))
      .toHaveTextContent('23.567 T3 de la ventana quedan fuera del cálculo')
  })

  it('sin OpenSearch muestra sin dato pero conserva el aviso de modo sombra', async () => {
    await enterCompliance({ available: false, shadow: true, validation: VALIDATION, from: VALIDATION.start, clamped: true })
    const card = await kpi(/Corroboración multi-fuente de T3/)
    expect(within(card).getByText('sin dato')).toBeInTheDocument()
    expect(within(card).getByText(/No determina bloqueos reales/)).toBeInTheDocument()
    expect(screen.queryByRole('region', { name: /Corroboración multi-fuente de T3/ })).not.toBeInTheDocument()
  })

  it('cerrado el período, sigue diciendo que no determina bloqueos', async () => {
    await enterCompliance(CORR, '2026-10-11T12:00:00Z')
    const card = await kpi(/Corroboración multi-fuente de T3/)
    expect(within(card).getByText(/No determina bloqueos reales/)).toHaveTextContent('validación cerrada el 10 oct, 20:40')
  })
})

// ── H57: vista consistente, auditable y honesta ──────────────────────────────

function h57Report(over: Record<string, unknown> = {}) {
  return {
    ...report(CORR),
    usuarios_por_rol: null, sesiones_activas: null,
    indice_usuarios: { reliable: false, reason: 'índice de usuarios vacío en Redis', members: 0 },
    policy_version: 'politica-prueba',
    regime: { id: 'R3', desde: '2026-10-09T02:42:16+00:00', descripcion: 'Gauge de la cuota real de AbuseIPDB (H55, d0c8f93)' },
    regimes_in_window: [{ id: 'R2', desde: '', descripcion: '' }, { id: 'R3', desde: '', descripcion: '' }],
    resumen: { obligaciones_del_sistema: 8, por_estado: { con_observacion: 1, parcial: 3, no_cubierto: 4 }, fuera_del_sistema: 6, generado: '2026-10-09T03:00:00Z' },
    nota_alcance: 'R-SOAR aporta evidencia técnica de apoyo. La evaluación de cumplimiento legal es de la organización.',
    latencia_descripcion: 'Latencia interna del Fast Path: procesamiento del motor, sin red ni Vector.',
    checklist: [{
      id: 'respuesta', article: 'Art. 8 e)', title: 'Medidas oportunas', status: 'con_observacion',
      evidence: 'La conciliación NO cierra', source: 'automático',
      meta: { ventana: 'ventana móvil de 24 h', unidad: 'decisiones', fuente: 'soc-decisions', actualizado: '2026-10-09T03:00:00Z', registros: '#nodos' },
    }],
    conciliacion_aprobaciones: {
      available: true, ips_bloqueadas: 244, acciones_de_bloqueo: 551, ips_derivadas: 531, decisiones_t3_derivadas: 20336,
      aprobaciones: { creadas_en_la_ventana: 1604, aprobadas: 0, rechazadas: 0, expiradas: 1325, pendientes: 279, recurrencias: 18732, eventos_sin_created_at: 0 },
      pendientes_ahora: 279,
      conciliacion: { available: true, estado: 'diferencia_explicada', causa: '570 decisiones de la ventana se sumaron a 101 aprobaciones abiertas antes de su inicio (TTL de 4 h); esas aprobaciones acumulan hasta 770 recurrencias', creadas_por_destino: 1604, creadas_por_documentos: 1604, recurrencias_por_documentos: 18732, recurrencias_por_contador: 18162, cierra: true, diferencia: 570, cota_borde: 770, regla: 'creadas por destino = creadas por documentos' },
    },
    integridad: {
      alcance: 'parcial',
      alcance_texto: 'verificación completa (completa) del 2026-10-09 04:04 UTC: soc-responses-* desde 2026-10-02, chain_seq 1 a 1699916, íntegra; soc-decisions-* desde 2026-10-03, chain_seq 1 a 2456573, íntegra; el índice legado soc-decisions (17,9 M documentos, cadena vieja) no se verificó en esta pasada',
      completa: { available: true, alcance: 'completa', ok: true, generated_at: '2026-10-09T04:04:48Z' },
      cola_en_vivo: report(CORR).cadenas,
      huecos_declarados: { available: true, gaps: [{ id: 'H54', hallazgo: 'H54', cadena: 'soc-responses', desde: '2026-10-08T03:32:41.987Z', hasta: '2026-10-08T03:32:45.538Z', registros: '0 a 5 registros R1/R2', detectable_por_cadena: false, descripcion: '' }] },
    },
    tiempos: { available: true, humano_s: { p50: null, p95: null, n: 0, detalle: 'sin datos: no hubo aprobaciones resueltas' } },
    historial_diario: { available: true, unidad: 'IPs distintas por día', dias: [{ dia: '2026-10-08', ips_bloqueadas: 244, ips_derivadas: 531, razon_bloqueo_sobre_derivacion: 0.46, aprobaciones_expiradas: 1325, regimenes: ['R1', 'R2', 'R3'] }] },
    ...over,
  }
}

async function enterH57(over: Record<string, unknown> = {}) {
  mockFetch({
    '/api/v1/auth/login': () => json(200, { access_token: 'tok', token_type: 'bearer', role: 'CISO' }),
    '/api/v1/dashboard/compliance': () => json(200, h57Report(over)),
  })
  const user = userEvent.setup()
  render(<AuthProvider><App /></AuthProvider>)
  await user.type(screen.getByLabelText('Usuario'), 'ana')
  await user.type(screen.getByLabelText('Contraseña'), 'una-clave-larga')
  await user.click(screen.getByRole('button', { name: 'Iniciar sesión' }))
  await screen.findByLabelText('Métricas de valor')
}

describe('Cumplimiento H57', () => {
  it('una fila con observación muestra su etiqueta y el contexto de la métrica', async () => {
    await enterH57()
    expect(screen.getAllByText('Con observación').length).toBeGreaterThan(0)
    expect(screen.queryByText('Con evidencia')).not.toBeInTheDocument()
    const link = screen.getByRole('link', { name: 'Ver registros' })
    expect(link).toHaveAttribute('href', '#nodos')
    expect(link.closest('p')).toHaveTextContent('ventana móvil de 24 h. Unidad: decisiones. Fuente: soc-decisions.')
  })

  it('usuarios y sesiones con el índice vacío dicen "dato no confiable", nunca 0', async () => {
    await enterH57()
    expect(screen.getByText(/Usuarios y sesiones: dato no confiable \(índice de usuarios vacío en Redis\)/)).toBeInTheDocument()
    const access = screen.getByRole('heading', { name: 'Control de acceso' }).closest('.panel') as HTMLElement
    expect(within(access).getByText('CISO / Gerencia').nextSibling).toHaveTextContent('dato no confiable')
    expect(within(access).getByText('Sesiones activas').nextSibling).toHaveTextContent('dato no confiable')
  })

  it('la conciliación de aprobaciones muestra unidades y si cierra', async () => {
    await enterH57()
    expect(screen.getByText('IPs distintas bloqueadas').nextSibling).toHaveTextContent('244')
    expect(screen.getByText('Recurrencias sumadas a aprobaciones abiertas').nextSibling).toHaveTextContent('18.732')
    expect(screen.getByText(/Diferencia explicada: 570 decisiones de la ventana se sumaron a 101 aprobaciones abiertas/)).toBeInTheDocument()
    expect(screen.getByText(/Foto actual, sin ventana: 279 aprobaciones pendientes ahora/)).toBeInTheDocument()
  })

  it('si la conciliación no cierra, lo dice', async () => {
    await enterH57({ conciliacion_aprobaciones: { ...h57Report().conciliacion_aprobaciones,
      conciliacion: { available: true, estado: 'no_cierra', causa: 'las aprobaciones creadas difieren: 1604 por destino y 1600 por documentos', cierra: false, diferencia: 4 } } })
    expect(screen.getByText(/La conciliación NO cierra: las aprobaciones creadas difieren: 1604 por destino y 1600 por documentos/)).toBeInTheDocument()
  })

  it('el panel de integridad declara su alcance y los huecos conocidos', async () => {
    await enterH57()
    const panel = screen.getByRole('status', { name: /verificación parcial/ })
    expect(panel).toHaveTextContent('Alcance: parcial')
    expect(panel).toHaveTextContent('soc-responses-* desde 2026-10-02, chain_seq 1 a 1699916')
    expect(panel).toHaveTextContent('no se verificó en esta pasada')
    expect(within(panel).getByText('H54').closest('li')).toHaveTextContent('0 a 5 registros R1/R2')
  })

  it('resumen de cobertura con política, régimen y nota de alcance', async () => {
    await enterH57()
    const cov = screen.getByRole('region', { name: 'Cobertura de lo que corresponde al sistema' })
    expect(cov).toHaveTextContent('8 obligaciones atendibles por R-SOAR: 1 con observación, 3 parcial, 4 no cubierto')
    expect(cov).toHaveTextContent('6 quedan fuera del sistema')
    expect(cov).toHaveTextContent('Política politica-prueba; régimen R3')
    expect(cov).toHaveTextContent('cruza 2 regímenes (R2, R3)')
    expect(cov).toHaveTextContent('evidencia técnica de apoyo')
  })

  it('tiempo humano sin datos e historial con regímenes', async () => {
    await enterH57()
    expect(screen.getByText('Apertura de la aprobación a resolución humana').nextSibling).toHaveTextContent('sin datos')
    const hist = screen.getByRole('region', { name: 'Historial diario (30 días)' })
    expect(within(hist).getByText('2026-10-08').closest('tr')).toHaveTextContent('R1, R2, R3')
  })
})
