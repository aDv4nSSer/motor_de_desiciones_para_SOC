import { Fragment } from 'react'
import { apiFetch } from '../api/client'
import type { NodeComponent, NodeStatus, WazuhAgent } from '../api/types'
import { EmptyState, ErrorNotice, Freshness, StatusBadge, TableSkeleton } from '../components/common'
import { formatTime } from '../lib/format'
import { usePolling } from '../lib/usePolling'

const OVERALL_TEXT = {
  ok: 'Todos los servicios operativos',
  degraded: 'Hay servicios degradados',
  down: 'Hay servicios caídos',
  unknown: 'Estado parcial: algunos chequeos sin dato',
  not_configured: 'Todos los servicios operativos',
} as const

function n(value: unknown): string {
  return typeof value === 'number' ? value.toLocaleString('es-CL') : 'sin dato'
}

function age(seconds: unknown): string {
  if (typeof seconds !== 'number') return 'sin dato'
  if (seconds < 90) return `${Math.round(seconds)} s`
  if (seconds < 5400) return `${Math.round(seconds / 60)} min`
  return `${(seconds / 3600).toFixed(1)} h`
}

/** Métricas relevantes de cada tipo de componente (sin volcar todo el JSON). */
function NodeMetrics({ c }: { c: NodeComponent }) {
  const m = c.metrics
  const rows: [string, string][] = []
  if (c.latency_ms !== null) rows.push(['Latencia', `${c.latency_ms.toFixed(1)} ms`])
  if (c.id === 'motor-soc') rows.push(['Modelo', String(m.model_version ?? 'sin dato')])
  if (c.id === 'redis') {
    rows.push(['Memoria', `${m.used_memory_human ?? '?'} de ${m.maxmemory_human || 'sin límite'}`])
    rows.push(['Clientes', n(m.connected_clients)])
  }
  if (c.id === 'opensearch') {
    rows.push(['Nodos', n(m.nodes)])
    rows.push(['Shards activos', n(m.active_shards)])
  }
  if ('stream' in m) {
    rows.push(['Stream', String(m.stream)])
    rows.push(['Sin procesar (lag)', n(m.lag)])
    rows.push(['Pendientes de ack', n(m.pending)])
    rows.push(['Último evento', `hace ${age(m.last_event_age_s)}`])
  }
  if (c.id === 'motor-watcher' && m.last_seen) rows.push(['Último heartbeat', formatTime(String(m.last_seen))])
  if (rows.length === 0) return null
  return (
    <dl className="kv">
      {rows.map(([k, v]) => (<Fragment key={k}><dt>{k}</dt><dd className="mono">{v}</dd></Fragment>))}
    </dl>
  )
}

function AgentsTable({ agents }: { agents: WazuhAgent[] }) {
  return (
    <div className="table-wrap">
      <table className="data">
        <caption className="sr-only">Agentes Wazuh</caption>
        <thead>
          <tr>
            <th scope="col">ID</th><th scope="col">Nombre</th><th scope="col">IP</th>
            <th scope="col">Estado</th><th scope="col">Versión</th><th scope="col">Último keepalive</th>
          </tr>
        </thead>
        <tbody>
          {agents.map((a) => (
            <tr key={a.id}>
              <td className="mono">{a.id}</td>
              <td>{a.name}{a.id === '000' && <span className="muted"> (manager)</span>}</td>
              <td className="mono">{a.ip ?? 'sin dato'}</td>
              <td><StatusBadge status={a.status === 'active' ? 'ok' : a.status === 'never_connected' ? 'unknown' : 'down'} /></td>
              <td className="mono">{a.version ?? 'sin dato'}</td>
              <td className="mono">{a.last_keepalive ? formatTime(a.last_keepalive) : 'sin dato'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function NodesView() {
  const poll = usePolling(() => apiFetch<NodeStatus>('/api/v1/dashboard/nodes'))
  const data = poll.data
  const wazuh = data?.components.find((c) => c.id === 'wazuh')
  const agents = wazuh?.metrics.agents ?? []

  return (
    <section aria-labelledby="nodes-title">
      <header className="view-header">
        <h2 id="nodes-title">Estado de nodos y servicios</h2>
        <Freshness
          updatedAt={poll.updatedAt} paused={poll.paused}
          onTogglePause={() => poll.setPaused(!poll.paused)} onRefresh={() => void poll.refresh()}
        />
      </header>
      <p className="view-intro">
        Chequeos en vivo desde el motor: Redis, OpenSearch, los consumidores de cada stream (por su lag),
        el vigilante FIM y los agentes Wazuh. Los procesos sin HTTP se observan por su consumer group.
      </p>

      {poll.error && <ErrorNotice message={poll.error} />}

      {poll.loading && !data ? (
        <TableSkeleton cols={4} />
      ) : !data ? (
        <EmptyState title="Sin datos de estado">El motor no respondió al chequeo de nodos.</EmptyState>
      ) : (
        <>
          <div className="panel overall" role="status">
            <StatusBadge status={data.overall} />
            <span className="big">{OVERALL_TEXT[data.overall]}</span>
            <span className="muted small when">Chequeado {formatTime(data.generated_at)}</span>
          </div>

          <ul className="node-grid">
            {data.components.map((c) => (
              <li key={c.id} className="panel node">
                <div className="node-head">
                  <h3>{c.name}</h3>
                  <span className="badge badge-outline host">{c.host}</span>
                </div>
                <StatusBadge status={c.status} />
                <p className="detail">{c.detail}</p>
                {typeof c.metrics.description === 'string' && <p className="muted small">{c.metrics.description}</p>}
                <NodeMetrics c={c} />
              </li>
            ))}
          </ul>

          <div className="section-title"><h3>Agentes Wazuh</h3></div>
          {agents.length > 0 ? (
            <AgentsTable agents={agents} />
          ) : (
            <EmptyState title="Sin lista de agentes">{wazuh?.detail ?? 'El chequeo de Wazuh no devolvió datos.'}</EmptyState>
          )}

          {!data.metrics_endpoint.available && (
            <p className="muted small footnote">
              Métricas Prometheus: {data.metrics_endpoint.detail}. Esta vista usa chequeos directos, no un scrape.
            </p>
          )}
        </>
      )}
    </section>
  )
}
