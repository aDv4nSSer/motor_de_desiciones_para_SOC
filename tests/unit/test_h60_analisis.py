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


RAW_D = RAW.replace("## aprobaciones_manuales_por_dia", """## d_pendientes_docs
event_time,src_ip,trace_id,dst_port,count,abuseipdb,abuseipdb_disponible,otx,otx_disponible,fuentes,nota_abuseipdb,nota_otx
2026-10-09T15:00:00Z,85.217.140.10,p1,22,1,30,True,4,True,otx,,
2026-10-09T16:00:00Z,85.217.140.11,p2,22,1,,False,2,True,otx,abuseipdb: omitido por throttling (no decisiva),
2026-10-09T17:00:00Z,85.217.140.11,p3,22,1,,False,2,True,otx,abuseipdb: omitido por throttling (no decisiva),
2026-10-09T18:00:00Z,69.5.169.7,p4,3389,1,90,True,0,True,abuseipdb,,
## d_ips_desde_corte
src_ip,docs,t2,t3,bloqueo,ttl_extendido,pendiente
85.217.140.10,3,1,2,0,0,1
85.217.140.11,4,2,2,0,0,2
85.217.140.99,9,0,9,3,6,0
69.5.169.7,1,0,1,0,0,1
## d_resoluciones
src_ip,evento,docs
85.217.140.10,approval_expired,1
## d_cola_actual
src_ip,created_at,occurrences,approval_level,nota
85.217.140.11,2026-10-09T16:00:00Z,2,N1,
## aprobaciones_manuales_por_dia""").replace(
    "event_time,src_ip,tier,accion,dst_port,ml_score,anomaly_score,risk_score\n"
    "2026-10-10T01:00:00Z,10.10.10.3,2,ninguna_infra_propia,55000,0.4,0.865,0.54\n"
    "2026-10-10T02:00:00Z,10.10.10.3,2,ninguna_infra_propia,55000,0.5,0.9,0.62\n"
    "2026-10-10T03:00:00Z,10.10.10.3,2,ninguna_infra_propia,55000,,,\n",
    "event_time,src_ip,tier,accion,dst_ip,dst_port,ml_score,anomaly_score,risk_score\n"
    "2026-10-10T01:00:00Z,10.10.10.3,2,ninguna_infra_propia,10.10.10.1,55000,0.4,0.865,0.54\n"
    "2026-10-10T02:00:00Z,10.10.10.3,2,ninguna_infra_propia,10.10.10.1,55000,0.5,0.9,0.62\n"
    "2026-10-10T03:00:00Z,10.10.10.3,2,ninguna_infra_propia,10.30.30.2,55000,,,\n")


def test_a_flujos_distintos_y_salvedad() -> None:
    tables, resumen = h60.analisis_a(h60.read_sections(RAW_D))
    flujos = tables["a_infra_flujos.csv"]
    assert [(f["dst_ip"], f["decisiones"]) for f in flujos] == [("10.10.10.1", 2), ("10.30.30.2", 1)]
    assert tables["a_infra_flujos_por_dia.csv"][0]["flujos_distintos"] == 2
    assert resumen[0].startswith("NO ES UNA TASA DE FALSOS POSITIVOS SOBRE TRÁFICO EXTERNO")


def test_d_fuente_faltante() -> None:
    assert h60.fuente_faltante({"fuentes": "otx", "abuseipdb": "30"}) == "AbuseIPDB < 50"
    assert h60.fuente_faltante({"fuentes": "otx", "abuseipdb": "", "nota_abuseipdb": "abuseipdb: omitido por throttling (x)"}) \
        == "AbuseIPDB no consultada (política de cuota)"
    presupuesto = "abuseipdb: omitido por throttling (presupuesto de la ventana agotado (6/6 en 600 s))"
    assert h60.fuente_faltante({"fuentes": "otx", "abuseipdb": "", "nota_abuseipdb": presupuesto}) \
        == "AbuseIPDB no consultada (presupuesto de la ventana agotado)"
    no_decisiva = "abuseipdb: omitido por throttling (no decisiva (OTX no corrobora: no puede cambiar R2))"
    assert h60.fuente_faltante({"fuentes": "", "abuseipdb": "", "otx": "0", "nota_abuseipdb": no_decisiva}) \
        == "AbuseIPDB no consultada (no decisiva: OTX no corrobora) y OTX sin pulsos"
    assert h60.fuente_faltante({"fuentes": "abuseipdb", "otx": "0"}) == "OTX sin pulsos"
    assert h60.fuente_faltante({"fuentes": "", "abuseipdb": "10", "otx": "0"}) == "AbuseIPDB < 50 y OTX sin pulsos"


def test_d_concentracion_por_24_y_hermanas() -> None:
    tables, resumen = h60.analisis_d(h60.read_sections(RAW_D))
    redes = tables["d_cola_por_red24.csv"]
    assert redes[0]["net24"] == "85.217.140.0/24" and redes[0]["ips_en_cola"] == 2 and redes[0]["registros_pendientes"] == 3
    assert redes[0]["pendientes_ahora"] == 1 and redes[0]["ips_hermanas_t2_t3"] == 3 and redes[0]["hermanas_autobloqueadas"] == 1
    assert redes[0]["pct_ips_en_cola"] == round(100 * 2 / 3, 2)
    her = {h["src_ip"]: h for h in tables["d_hermanas_top5.csv"]}
    assert her["85.217.140.99"]["en_cola"] is False and her["85.217.140.10"]["expiradas"] == 1
    assert "OTX sin pulsos: 1" in resumen[2] and "AbuseIPDB < 50: 1" in resumen[2]
    assert "1 de 1 pendientes actuales (100.0%)" in resumen[1]


def test_archivo_fuera_de_git_con_manifiesto(tmp_path) -> None:
    raw = tmp_path / "crudo.txt"
    raw.write_text(RAW_D, encoding="utf-8")
    out, arch = tmp_path / "repo_out", tmp_path / "archivo"
    assert h60.escribir(raw, out, arch) == 0
    man = (out / "manifiesto_h60.md").read_text(encoding="utf-8")
    assert not list(out.glob("*.csv"))                     # los CSV no quedan en --out
    dirs = list(arch.iterdir())
    assert len(dirs) == 1 and (dirs[0] / "extraccion_cruda.txt").exists()
    f = dirs[0] / "d_cola_por_red24.csv"
    assert h60._sha256(f) in man


def test_archivo_dentro_de_git_aborta(tmp_path) -> None:
    raw = tmp_path / "crudo.txt"
    raw.write_text(RAW_D, encoding="utf-8")
    assert h60.escribir(raw, tmp_path / "o", ROOT / "reports" / "no_deberia_crearse") == 1
    assert not (ROOT / "reports" / "no_deberia_crearse").exists()
