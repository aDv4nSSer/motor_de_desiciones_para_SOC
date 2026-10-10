#!/usr/bin/env python3
"""
graficar_metricas.py — CSV y PNG de las métricas de la tesis (H59).

Toma la salida de extraer_metricas.py (secciones `## nombre` + CSV) y, si se
pasa, el CSV de consumo de AbuseIPDB por día y tier sacado del worker.log;
escribe un CSV por sección y un PNG por métrica en --salida, con una línea
vertical en cada corte de régimen de motor/regimes.py (antes y después de un
corte no son el mismo sistema).

Reproducible: mismas entradas, mismos archivos. Requiere matplotlib
(probado con 3.9.2), fuera de requirements.txt porque no corre en producción.

Uso (local):
    python3 scripts/metrics/graficar_metricas.py metricas.txt --salida reports/metricas/2026-10-10

Motor SOC — Tesis UBO.
"""
from __future__ import annotations

import argparse
import csv
import io
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

from regimes import REGIMES


def split_sections(text: str) -> dict[str, list[dict[str, str]]]:
    """{'nombre': filas} a partir del texto con secciones `## nombre`."""
    out: dict[str, list[dict[str, str]]] = {}
    name, buf = None, []
    for line in text.splitlines() + ["## __fin__"]:
        if line.startswith("## "):
            if name:
                out[name] = list(csv.DictReader(io.StringIO("\n".join(buf))))
            name, buf = line[3:].split(" ")[0].strip(), []
        elif name:
            buf.append(line)
    return out


def _ts(s: str) -> datetime:
    s = s.replace("Z", "+00:00")
    d = datetime.fromisoformat(s[:10] if len(s) == 10 else s)
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _regimes(ax, start: datetime, end: datetime) -> None:
    for rid, since, _ in REGIMES:
        if start <= since <= end:
            ax.axvline(since, color="0.4", linestyle="--", linewidth=0.8)
            ax.text(since, ax.get_ylim()[1], f" {rid}", va="top", fontsize=7, color="0.3")


def plot(sections: dict[str, list[dict[str, str]]], outdir: Path) -> list[Path]:
    """Un PNG por métrica. Devuelve las rutas escritas."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    written = []

    def save(fig, name):
        p = outdir / f"{name}.png"
        fig.tight_layout()
        fig.savefig(p, dpi=130, metadata={"Software": None, "CreationDate": None})
        plt.close(fig)
        written.append(p)

    rows = sections.get("tiers_por_hora") or []
    if rows:
        x = [_ts(r["hora_utc"]) for r in rows]
        fig, ax = plt.subplots(figsize=(10, 4))
        ax.stackplot(x, *[[int(r[f"t{i}"]) for r in rows] for i in range(4)], labels=["T0", "T1", "T2", "T3"])
        ax.set_ylabel("decisiones por hora")
        ax.set_title("Decisiones del Fast Path por tier (soc-decisions-*)")
        ax.legend(loc="upper left", fontsize=8)
        _regimes(ax, x[0], x[-1])
        save(fig, "tiers_por_hora")

    rows = sections.get("latencia_por_dia") or []
    if rows:
        x = [_ts(r["dia_utc"]) for r in rows]
        fig, ax = plt.subplots(figsize=(10, 4))
        for p in ("p50", "p95", "p99"):
            ax.plot(x, [float(r[p]) if r[p] else None for r in rows], marker="o", label=p)
        ax.set_ylabel("latencia del Fast Path (ms)")
        ax.set_title("Latencia por día (incluye los días de restart; ver PENDIENTES §6)")
        ax.legend(fontsize=8)
        _regimes(ax, x[0], x[-1])
        save(fig, "latencia_por_dia")

    rows = sections.get("respuesta_por_dia") or []
    if rows:
        x = [_ts(r["dia_utc"]) for r in rows]
        fig, ax = plt.subplots(figsize=(10, 4))
        for col, label in (("ips_bloqueadas_auto", "bloqueo automático"), ("ips_derivadas_aprobacion", "derivadas a aprobación"),
                           ("ips_aprobacion_expirada", "aprobación expirada")):
            ax.plot(x, [int(r[col]) for r in rows], marker="o", label=label)
        ax.set_ylabel("IPs distintas por día")
        ax.set_title("Destino de la respuesta en IPs distintas (soc-responses-*); el último día es parcial")
        ax.legend(fontsize=8)
        _regimes(ax, x[0], x[-1])
        save(fig, "respuesta_por_dia")

    rows = sections.get("abuseipdb_por_dia") or []
    if rows:
        days = sorted({r["fecha"] for r in rows})
        tiers = sorted({r["tier"] for r in rows})
        fig, ax = plt.subplots(figsize=(8, 4))
        bottom = [0] * len(days)
        for t in tiers:
            vals = [sum(int(r["llamadas"]) for r in rows if r["fecha"] == d and r["tier"] == t) for d in days]
            ax.bar(days, vals, bottom=bottom, label=f"tier {t}")
            bottom = [b + v for b, v in zip(bottom, vals)]
        ax.set_ylabel("consultas a AbuseIPDB")
        ax.set_title("Consultas reales a AbuseIPDB por día local y tier (desde R4)")
        ax.legend(fontsize=8)
        save(fig, "abuseipdb_por_dia")
    return written


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("entrada", type=Path, help="salida de extraer_metricas.py")
    ap.add_argument("--abuseipdb", type=Path, help="CSV fecha,tier,llamadas (del worker.log)")
    ap.add_argument("--salida", type=Path, required=True)
    args = ap.parse_args()
    sections = split_sections(args.entrada.read_text())
    if args.abuseipdb:
        sections["abuseipdb_por_dia"] = list(csv.DictReader(args.abuseipdb.open()))
    args.salida.mkdir(parents=True, exist_ok=True)
    for name, rows in sections.items():
        if not rows:
            continue
        with (args.salida / f"{name}.csv").open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
    for p in plot(sections, args.salida):
        print(p)
    return 0


if __name__ == "__main__":
    sys.exit(main())
