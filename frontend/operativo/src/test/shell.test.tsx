import { describe, expect, it } from 'vitest'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import App from '../App'
import { AuthProvider } from '../auth/AuthContext'
import type { Role } from '../api/types'
import { json, mockFetch } from './helpers'

type Handler = Parameters<typeof mockFetch>[0][string]

const EMPTY: Record<string, Handler> = {
  '/api/v1/dashboard/decisions': () => json(200, []),
  '/api/v1/dashboard/blocks/recent': () => json(200, []),
  '/api/v1/dashboard/stats': () => json(200, { available: true, window_minutes: 60, total_decisiones: 0, por_tier: {} }),
}

const TAIL = {
  available: true, verified: 2001, from_seq: 10, to_seq: 2010, ok: true, problems: [],
  head_hash: 'abc123', head_time: '2026-10-03T12:00:00Z', cutover: null,
}

async function enter(role: Role, routes: Record<string, Handler> = {}, hash = '') {
  const mock = mockFetch({
    '/api/v1/auth/login': () => json(200, { access_token: 'tok', token_type: 'bearer', role }),
    '/api/v1/auth/logout': () => json(200, { status: 'ok' }),
    ...routes,
    ...EMPTY,
  })
  window.location.hash = hash
  const user = userEvent.setup()
  render(<AuthProvider><App /></AuthProvider>)
  await user.type(screen.getByLabelText('Usuario'), 'ana')
  await user.type(screen.getByLabelText('Contraseña'), 'una-clave-larga')
  await user.click(screen.getByRole('button', { name: 'Iniciar sesión' }))
  await screen.findByRole('navigation', { name: 'Secciones' })
  return { user, ...mock }
}

function menuLabels(): string[] {
  const nav = screen.getByRole('navigation', { name: 'Secciones' })
  return within(nav).getAllByRole('link').map((a) => a.textContent ?? '')
}

describe('menú según rol', () => {
  it('N1 ve solo Operación', async () => {
    await enter('N1')
    expect(menuLabels()).toEqual(['Alertas', 'Aprobaciones', 'Casos', 'Estado de nodos'])
  })

  it('N2 suma auditoría y usuarios, no cumplimiento', async () => {
    await enter('N2')
    const labels = menuLabels()
    expect(labels).toContain('Historial y auditoría')
    expect(labels).toContain('Usuarios y sesiones')
    expect(labels).not.toContain('Cumplimiento')
    expect(labels).not.toContain('Tendencias')
  })

  it('CISO entra a su resumen de cumplimiento por defecto', async () => {
    await enter('CISO', {
      '/api/v1/dashboard/compliance': () => json(503, {}),
    })
    expect(await screen.findByRole('heading', { name: 'Cumplimiento Ley 21.663' })).toBeInTheDocument()
    expect(menuLabels()).toContain('Tendencias')
  })
})

describe('rol-gating de rutas (no solo ocultar el link)', () => {
  it('N1 que escribe #usuarios ve acceso restringido y no se llama al endpoint', async () => {
    const { calls } = await enter('N1', {}, '#usuarios')
    expect(await screen.findByRole('heading', { name: 'Acceso restringido' })).toBeInTheDocument()
    expect(screen.getByText(/requiere rol N2 o superior/)).toBeInTheDocument()
    expect(calls.some((c) => c.url.startsWith('/api/v1/dashboard/users'))).toBe(false)
    expect(calls.some((c) => c.url.startsWith('/api/v1/dashboard/sessions'))).toBe(false)
  })

  it('N2 que navega a #cumplimiento no monta la vista CISO', async () => {
    const { calls } = await enter('N2')
    act(() => { window.location.hash = '#cumplimiento'; window.dispatchEvent(new HashChangeEvent('hashchange')) })
    expect(await screen.findByText(/requiere rol CISO\./)).toBeInTheDocument()
    expect(calls.some((c) => c.url.startsWith('/api/v1/dashboard/compliance'))).toBe(false)
  })

  it('N1 a #tendencias tampoco', async () => {
    const { calls } = await enter('N1', {}, '#tendencias')
    expect(await screen.findByRole('heading', { name: 'Acceso restringido' })).toBeInTheDocument()
    expect(calls.some((c) => c.url.startsWith('/api/v1/dashboard/trends'))).toBe(false)
  })
})

describe('cierre de sesión', () => {
  it('revoca la sesión en el servidor con el token vigente', async () => {
    const { user, calls } = await enter('N1')
    await user.click(screen.getByRole('button', { name: /Cerrar sesión/ }))
    await screen.findByRole('button', { name: 'Iniciar sesión' })
    const logout = calls.find((c) => c.url === '/api/v1/auth/logout')
    expect(logout).toBeDefined()
    expect(new Headers(logout!.init?.headers).get('Authorization')).toBe('Bearer tok')
  })
})

describe('historial y auditoría', () => {
  it('muestra la cadena verificada y, como N2, la vista parcial', async () => {
    await enter('N2', {
      '/api/v1/dashboard/audit/chain': () => json(200, {
        verified_at: '2026-10-03T12:00:00Z', tail_size: 2000, full_verification: '',
        chains: { responses: { ...TAIL, pattern: 'soc-responses-*' }, decisions: { ...TAIL, pattern: 'soc-decisions-*' } },
      }),
      '/api/v1/dashboard/audit/trace/': () => json(200, {
        trace_id: 'abcd1234-0000', available: true, scope: 'partial', hidden_events: 2, decisions: [],
        events: [{ doc: { event_type: 'response', event_time: '2026-10-03T12:00:00Z', accion_recomendada: 'bloqueo_ip' },
          verification: { content_ok: false, prev_link_ok: true, next_link_ok: null, chain_seq: 7, hash: 'ffee' } }],
      }),
    }, '#auditoria')
    expect(await screen.findAllByText('Cadena verificada ✓')).toHaveLength(2)
    expect(screen.queryByText('Bitácora de accesos')).not.toBeInTheDocument()

    const user = userEvent.setup()
    await user.type(screen.getByLabelText('Buscar por trace_id'), 'abcd1234-0000')
    await user.click(screen.getByRole('button', { name: /Buscar/ }))
    expect(await screen.findByText('Contenido íntegro: NO coincide')).toBeInTheDocument()
    expect(screen.getByText(/2 eventos de control de acceso/)).toBeInTheDocument()
  })

  it('una cadena rota no se muestra como verificada', async () => {
    await enter('CISO', {
      '/api/v1/dashboard/audit/chain': () => json(200, {
        verified_at: '2026-10-03T12:00:00Z', tail_size: 2000, full_verification: '',
        chains: {
          responses: { ...TAIL, pattern: 'soc-responses-*', ok: false, problems: ['chain_seq 26: el hash no corresponde al contenido (alterado)'] },
          decisions: { ...TAIL, pattern: 'soc-decisions-*', available: false, ok: null, verified: 0 },
        },
      }),
      '/api/v1/dashboard/audit/access': () => json(200, { available: true, items: [] }),
    }, '#auditoria')
    expect(await screen.findByText('Cadena con problemas')).toBeInTheDocument()
    expect(screen.getByText('No se pudo verificar')).toBeInTheDocument()
    expect(screen.queryByText('Cadena verificada ✓')).not.toBeInTheDocument()
    expect(screen.getByText(/alterado/)).toBeInTheDocument()
  })

  it('el trace_id con formato inválido no se envía', async () => {
    const { calls } = await enter('CISO', {
      '/api/v1/dashboard/audit/chain': () => json(503, {}),
      '/api/v1/dashboard/audit/access': () => json(200, { available: true, items: [] }),
    }, '#auditoria')
    const user = userEvent.setup()
    await user.type(screen.getByLabelText('Buscar por trace_id'), "x' OR 1=1")
    expect(screen.getByRole('button', { name: /Buscar/ })).toBeDisabled()
    expect(calls.some((c) => c.url.includes('/audit/trace/'))).toBe(false)
  })
})

describe('usuarios y sesiones', () => {
  it('N2 solo puede crear N1 y el alta envía lo que escribió', async () => {
    let posted: unknown = null
    const { user } = await enter('N2', {
      '/api/v1/dashboard/users': (_url, init) => {
        if (init?.method === 'POST') { posted = JSON.parse(String(init.body)); return json(201, {}) }
        return json(200, { assignable_roles: ['N1'], items: [
          { username: 'ana', role: 'N2', created_at: '2026-09-01T00:00:00Z', disabled: false, active_sessions: 1, manageable: false, is_self: true },
          { username: 'jefa', role: 'CISO', created_at: '2026-09-01T00:00:00Z', disabled: false, active_sessions: 0, manageable: false, is_self: false },
        ] })
      },
      '/api/v1/dashboard/sessions': () => json(200, { items: [] }),
    }, '#usuarios')
    const roleSelect = await screen.findByLabelText('Rol')
    expect(within(roleSelect).getAllByRole('option').map((o) => o.textContent)).toEqual(['Operador N1'])
    expect(screen.getByText('Fuera de tu alcance')).toBeInTheDocument()

    await user.type(screen.getByLabelText('Usuario', { selector: '#nu-username' }), 'op.nuevo')
    await user.type(screen.getByLabelText('Contraseña inicial'), 'corta')
    expect(screen.getByRole('button', { name: /Crear usuario/ })).toBeDisabled()
    await user.type(screen.getByLabelText('Contraseña inicial'), '-ahora-larga')
    await user.type(screen.getByLabelText('Confirmar contraseña'), 'corta-ahora-larga')
    await user.click(screen.getByRole('button', { name: /Crear usuario/ }))
    await waitFor(() => expect(posted).toEqual({ username: 'op.nuevo', password: 'corta-ahora-larga', role: 'N1' })) // pragma: allowlist secret (contraseña ficticia de test)
    expect(await screen.findByText(/op.nuevo creado con rol N1/)).toBeInTheDocument()
  })

  it('un 403 del servidor se muestra tal cual, sin aparentar éxito', async () => {
    const { user } = await enter('CISO', {
      '/api/v1/dashboard/users/op': () => json(409, { detail: 'Es el único CISO habilitado: el sistema no puede quedar sin CISO.' }),
      '/api/v1/dashboard/users': () => json(200, { assignable_roles: ['N1', 'N2', 'CISO'], items: [
        { username: 'op', role: 'CISO', created_at: '2026-09-01T00:00:00Z', disabled: false, active_sessions: 0, manageable: true, is_self: false },
      ] }),
      '/api/v1/dashboard/sessions': () => json(200, { items: [] }),
    }, '#usuarios')
    await user.click(await screen.findByRole('button', { name: /Dar de baja/ }))
    await user.click(screen.getByRole('button', { name: 'Confirmar' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('único CISO habilitado')
  })
})

describe('estado de nodos', () => {
  it('muestra cada componente con estado en texto, no solo color', async () => {
    await enter('N1', {
      '/api/v1/dashboard/nodes': () => json(200, {
        generated_at: '2026-10-03T12:00:00Z', overall: 'down',
        metrics_endpoint: { available: false, detail: 'Ningún servicio expone /metrics Prometheus todavía' },
        components: [
          { id: 'redis', name: 'Redis', host: '.140', status: 'ok', detail: 'PING 0.8 ms', latency_ms: 0.8, metrics: {} },
          { id: 'response-worker', name: 'response-worker', host: '.140', status: 'down', detail: 'atrasado: 60.000 sin procesar', latency_ms: null,
            metrics: { stream: 'soc:response:tasks', lag: 60000, pending: 3, last_event_age_s: 2 } },
          { id: 'wazuh', name: 'Wazuh', host: '.139', status: 'not_configured', detail: 'Sin credenciales', latency_ms: null, metrics: { agents: [] } },
        ],
      }),
    }, '#nodos')
    expect(await screen.findByText('Hay servicios caídos')).toBeInTheDocument()
    expect(screen.getByText('atrasado: 60.000 sin procesar')).toBeInTheDocument()
    expect(screen.getAllByText('Caído').length).toBeGreaterThan(0)
    expect(screen.getByText('No configurado')).toBeInTheDocument()
  })
})
