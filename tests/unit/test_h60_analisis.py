"""
H60: derivados locales de scripts/metrics/analisis_h60.py (análisis de solo
lectura A, B y C) sobre tablas crudas sintéticas. La extracción en .140 no se
prueba acá: solo lee OpenSearch.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "motor"))
_spec = importlib.util.spec_from_file_location("analisis_h60", ROOT / "scripts" / "metrics" / "analisis_h60.py")
h60 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(h60)

RAW = """## parametros
desde,hasta,extraido_utc,min_fuentes_autobloqueo,stale_max_s,safelist_extra_n
2026-10-03T00:00:00Z,,2026-10-10T16:00:00+00:00,2,3600,0
## tier_por_dia
dia_utc,tier,docs,ips,docs_infra,ips_infra
2026-10-10,2,100,40,10,1
2026-10-10,3,20,8,0,0
## infra_docs
event_time,src_ip,tier,accion,dst_port,ml_score,anomaly_score,risk_score
2026-10-10T01:00:00Z,10.10.10.3,2,ninguna_infra_propia,55000,0.4,0.865,0.54
2026-10-10T02:00:00Z,10.10.10.3,2,ninguna_infra_propia,55000,0.5,0.9,0.62
2026-10-10T03:00:00Z,10.10.10.3,2,ninguna_infra_propia,55000,,,
## t2_corroboradas_docs
event_time,src_ip,trace_id,dst_port,abuseipdb,otx,fuentes,cache,event_age_s,case_id
2026-10-10T01:00:00Z,91.92.42.173,t1,22,100,26,abuseipdb+otx,True,5,c1
2026-10-10T02:00:00Z,91.92.42.80,t2,22,100,50,abuseipdb+otx,True,5,c2
2026-10-10T03:00:00Z,91.92.42.80,t3,23,100,50,abuseipdb+otx,True,5,c2
2026-10-10T04:00:00Z,45.9.20.7,t4,80,90,3,abuseipdb+otx,True,7200,
2026-10-10T05:00:00Z,8.8.4.4,t5,443,60,4,abuseipdb+otx,True,5,c3
## ips_autobloqueadas
src_ip,primer_bloqueo
8.8.4.4,2026-10-09T10:00:00.000Z
1.1.1.1,2026-10-09T08:00:00.000Z
4.4.4.4,2026-10-10T01:00:00.000Z
## t3_ip_dia
dia_utc,src_ip,docs,bloqueo_nuevo,ttl_extendido,pendiente
2026-10-10,1.1.1.1,5,1,4,0
2026-10-10,2.2.2.2,3,0,3,0
2026-10-10,3.3.3.3,2,0,0,2
2026-10-10,4.4.4.4,1,1,0,0
## aprobaciones_manuales_por_dia
dia_utc,docs,ips,ejecutadas
## ips_por_hora
hora_utc,tier,decisiones,decisiones_externas,ips_externas,decisiones_infra,ips_infra
2026-10-10T00:00:00.000Z,2,10,8,5,2,1
"""


def _sec():
    return h60.read_sections(RAW)


def test_a_infra_pct_y_percentiles() -> None:
    tables, resumen = h60.analisis_a(_sec())
    dia = tables["a_infra_por_dia.csv"]
    assert dia[0]["decisiones_infra"] == 3 and dia[0]["decisiones_tier"] == 100 and dia[0]["pct_infra"] == 3.0
    assert dia[0]["unidas_a_decision"] == 2 and dia[0]["anom_p50"] in (0.865, 0.9)
    assert tables["a_infra_pares.csv"][0] == {"src_ip": "10.10.10.3", "dst_port": "55000", "decisiones": 3,
                                              "t2": 3, "t3": 0, "pct_del_total_infra": 100.0}
    assert any("no representa tráfico externo benigno" in r for r in resumen)


def test_b_agrupa_por_24_y_estima_bloqueos_si_fueran_t3() -> None:
    tables, resumen = h60.analisis_b(_sec())
    ips = {r["src_ip"]: r for r in tables["b_t2_corroboradas_ips.csv"]}
    assert ips["91.92.42.80"]["decisiones"] == 2 and ips["91.92.42.80"]["puertos"] == "22:1 23:1"
    assert ips["91.92.42.173"]["seria_bloqueo_automatico_si_t3"] is True
    assert ips["45.9.20.7"]["seria_bloqueo_automatico_si_t3"] is False  # solo eventos antiguos (stale)
    assert ips["8.8.4.4"]["seria_ttl_extendido_si_t3"] is True          # ya bloqueada antes
    redes = {r["net24"]: r for r in tables["b_t2_corroboradas_redes24.csv"]}
    assert redes["91.92.42.0/24"]["ips"] == 2 and redes["91.92.42.0/24"]["campana_candidata"] is True
    assert "1 /24 con 2 o más IPs" in resumen[0]
    assert "2 IPs serían bloqueo automático nuevo y 1 ya estaban bloqueadas" in resumen[1]


def test_c_separa_bloqueo_nuevo_de_ttl_extendido() -> None:
    tables, _ = h60.analisis_c(_sec())
    d = tables["c_autonomia_por_dia.csv"][0]
    assert d["ips_t3_externas"] == 4
    assert d["ips_bloqueo_nuevo"] == 2 and d["ips_ttl_extendido"] == 2 and d["ips_solo_ttl_extendido"] == 1
    assert d["ips_pendientes_aprobacion"] == 1
    assert d["ips_primer_bloqueo_en_ventana"] == 1 and d["ips_rebloqueo_tras_vencer_ttl"] == 1  # 4.4.4.4 nueva, 1.1.1.1 re-bloqueo
    assert d["pct_autonomia_bloqueo_nuevo"] == 50.0 and d["pct_autonomia_incl_ttl"] == 75.0
    assert tables["c_ips_por_hora.csv"][0]["regimen"] == "R4"


def test_infra_query_cubre_privadas_y_safelist() -> None:
    q = h60.infra_query({"200.54.12.139"})
    prefixes = {c["prefix"]["src_ip"] for c in q["bool"]["should"] if "prefix" in c}
    assert {"10.", "192.168.", "172.16.", "172.31."} <= prefixes
    assert {"terms": {"src_ip": ["200.54.12.139"]}} in q["bool"]["should"]
