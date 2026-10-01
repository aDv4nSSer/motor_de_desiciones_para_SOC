import { Plug } from '@phosphor-icons/react'

/** Iris Web no está desplegado ni integrado (verificado 2026-09-30 en .139 y
 *  .140). La especificación lo define como fuente de los casos, sin módulo
 *  propio de respaldo: hasta que exista, esta vista no muestra datos. */
export function CasesView() {
  return (
    <section aria-labelledby="cases-title">
      <header className="view-header">
        <h2 id="cases-title">Casos</h2>
      </header>
      <div className="empty empty-integration">
        <Plug size={32} weight="duotone" aria-hidden="true" />
        <p className="empty-title">Pendiente de integración con Iris Web</p>
        <p className="muted">
          Los casos se gestionarán en Iris Web, que todavía no está desplegado. Cuando esté integrado,
          aquí aparecerán los casos abiertos con su enlace directo a Iris.
        </p>
      </div>
    </section>
  )
}
