const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}$/

/** Red /24 de una IPv4 ("91.92.42.173" -> "91.92.42.0/24"); null si no es IPv4. */
export function net24Of(ip: string | null | undefined): string | null {
  const m = ip ? IPV4.exec(ip) : null
  return m ? `${m[1]}.${m[2]}.${m[3]}.0/24` : null
}

/** Agrupa por red conservando el orden de primera aparición. Solo presentación. */
export function groupByNet<T>(items: T[], netOf: (item: T) => string): { net: string; items: T[] }[] {
  const m = new Map<string, T[]>()
  for (const it of items) {
    const net = netOf(it)
    m.set(net, [...(m.get(net) ?? []), it])
  }
  return [...m.entries()].map(([net, group]) => ({ net, items: group }))
}
