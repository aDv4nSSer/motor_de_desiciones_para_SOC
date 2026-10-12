"""Análisis de la muestra de precisión del auto-bloqueo (se ejecuta DESPUÉS de etiquetar; no toca producción).

Uso:
    python3 analizar_etiquetado.py --ficha ficha_ciega.csv [--segundo ficha_segundo_etiquetador.csv]

Calcula, sobre el CSV etiquetado:
- precisión estricta (malicioso / n) y ampliada ((malicioso + escáner de investigación) / n), con intervalo
  exacto de Clopper-Pearson al 95 %, tratando los indeterminados como no positivos (cota pesimista);
- tasa de falsos positivos (falso positivo / n) con su intervalo;
- indeterminados aparte, con cotas pesimista y optimista de ambas precisiones;
- sensibilidad por /24: precisión dando el mismo peso a cada /24 distinto y cuántos /24 hay en la muestra;
- acuerdo con el segundo etiquetador sobre los ids en común: % de acuerdo y kappa de Cohen;
- tasa de corrección de las reglas: pre_etiquetas que el etiquetador humano cambió.
"""
import argparse
import csv
import math
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path

ETIQUETAS = ("malicioso", "escáner de investigación", "falso positivo", "indeterminado")
NIVEL_CONFIANZA = 0.95


def normalizar(texto: str) -> str:
    """Minúsculas y sin acentos, para comparar etiquetas escritas a mano."""
    base = unicodedata.normalize("NFD", (texto or "").strip().lower())
    return "".join(c for c in base if unicodedata.category(c) != "Mn")


CANON = {normalizar(e): e for e in ETIQUETAS} | {"escaner": "escáner de investigación", "fp": "falso positivo"}


def canonica(texto: str) -> str | None:
    return CANON.get(normalizar(texto))


def _cola_binomial(k: int, n: int, p: float, superior: bool) -> float:
    """P(X >= k) si superior, P(X <= k) si no, con X ~ Binomial(n, p)."""
    def pmf(i: int) -> float:
        if p in (0.0, 1.0):
            return 1.0 if (i == 0 and p == 0.0) or (i == n and p == 1.0) else 0.0
        return math.exp(math.lgamma(n + 1) - math.lgamma(i + 1) - math.lgamma(n - i + 1)
                        + i * math.log(p) + (n - i) * math.log1p(-p))
    return sum(pmf(i) for i in (range(k, n + 1) if superior else range(k + 1)))


def clopper_pearson(x: int, n: int, nivel: float = NIVEL_CONFIANZA) -> tuple[float, float]:
    """Intervalo exacto de Clopper-Pearson para x éxitos en n pruebas (bisección sobre las colas binomiales)."""
    if n == 0:
        return (math.nan, math.nan)
    alfa = 1 - nivel

    def buscar(f, objetivo: float, creciente: bool) -> float:
        lo, hi = 0.0, 1.0
        for _ in range(80):
            mid = (lo + hi) / 2
            if (f(mid) < objetivo) == creciente:
                lo = mid
            else:
                hi = mid
        return (lo + hi) / 2
    inf = 0.0 if x == 0 else buscar(lambda p: _cola_binomial(x, n, p, True), alfa / 2, True)
    sup = 1.0 if x == n else buscar(lambda p: _cola_binomial(x, n, p, False), alfa / 2, False)
    return (inf, sup)


def kappa_cohen(a: list[str], b: list[str]) -> float:
    """Kappa de Cohen entre dos etiquetadores sobre los mismos ítems."""
    n = len(a)
    po = sum(x == y for x, y in zip(a, b)) / n
    ca, cb = Counter(a), Counter(b)
    pe = sum((ca[c] / n) * (cb[c] / n) for c in set(ca) | set(cb))
    return 1.0 if pe == 1 else (po - pe) / (1 - pe)


def fila(x: int, n: int) -> str:
    lo, hi = clopper_pearson(x, n)
    return f"{x}/{n} = {100 * x / n:.1f} % (IC 95 % {100 * lo:.1f}–{100 * hi:.1f} %)"


def leer(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def etiquetadas(filas: list[dict], nombre: str) -> dict[str, str]:
    malas = [r["id"] for r in filas if canonica(r.get("etiqueta", "")) is None]
    if malas:
        raise SystemExit(f"{nombre}: etiqueta vacía o inválida en {len(malas)} ids: {malas[:10]} (válidas: {', '.join(ETIQUETAS)})")
    return {r["id"]: canonica(r["etiqueta"]) for r in filas}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ficha", required=True, type=Path)
    ap.add_argument("--segundo", type=Path)
    a = ap.parse_args()
    filas = leer(a.ficha)
    et = etiquetadas(filas, "ficha")
    n = len(filas)
    c = Counter(et.values())
    m, e, fp, ind = c["malicioso"], c["escáner de investigación"], c["falso positivo"], c["indeterminado"]
    print(f"# Resultado (n = {n}; IC de Clopper-Pearson al 95 %)\n")
    print("Conteo: " + ", ".join(f"{k} {c[k]}" for k in ETIQUETAS) + "\n")
    print(f"- Precisión estricta (malicioso / n), indeterminados como no positivos: {fila(m, n)}")
    print(f"- Precisión ampliada ((malicioso + escáner) / n), ídem: {fila(m + e, n)}")
    print(f"- Tasa de falsos positivos (falso positivo / n): {fila(fp, n)}")
    print(f"- Indeterminados aparte: {ind}/{n}. Estricta entre {100 * m / n:.1f} % (pesimista) y {100 * (m + ind) / n:.1f} % (optimista); "
          f"ampliada entre {100 * (m + e) / n:.1f} % y {100 * (m + e + ind) / n:.1f} %.")
    det = n - ind
    if det:
        print(f"- Solo con determinados (n = {det}): estricta {fila(m, det)}; ampliada {fila(m + e, det)}; falsos positivos {fila(fp, det)}")
    redes = defaultdict(list)
    for r in filas:
        redes[r["net24"]].append(et[r["id"]])
    estricta = sum(v.count("malicioso") / len(v) for v in redes.values()) / len(redes)
    ampliada = sum((v.count("malicioso") + v.count("escáner de investigación")) / len(v) for v in redes.values()) / len(redes)
    print(f"- Sensibilidad por /24: {len(redes)} /24 distintos en la muestra; precisión con el mismo peso por /24: "
          f"estricta {100 * estricta:.1f} %, ampliada {100 * ampliada:.1f} %.")
    pre = [r for r in filas if (r.get("pre_etiqueta") or "").strip()]
    if pre:
        cambiadas = sum(canonica(r["pre_etiqueta"]) != et[r["id"]] for r in pre)
        print(f"- Reglas de preetiquetado: {len(pre)} aplicadas; el etiquetador humano corrigió {cambiadas} ({100 * cambiadas / len(pre):.1f} %).")
    else:
        print("- Reglas de preetiquetado: ninguna aplicada.")
    if a.segundo:
        et2 = etiquetadas(leer(a.segundo), "segundo etiquetador")
        comunes = [i for i in et2 if i in et]
        if len(comunes) != len(et2):
            raise SystemExit("el segundo etiquetador trae ids que no están en la ficha principal")
        x, y = [et[i] for i in comunes], [et2[i] for i in comunes]
        acuerdo = sum(p == q for p, q in zip(x, y))
        print(f"- Acuerdo con el segundo etiquetador (n = {len(comunes)}): {acuerdo}/{len(comunes)} = {100 * acuerdo / len(comunes):.1f} %, "
              f"kappa de Cohen = {kappa_cohen(x, y):.3f}.")


if __name__ == "__main__":
    main()
