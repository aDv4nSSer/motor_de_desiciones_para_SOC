"""
H50: classtype de Suricata -> MITRE ATT&CK (motor/classtype_attack.yaml)
wireado a soc-decisions y al Active Response de Wazuh.

Cubre la cadena completa con mocks (sin Redis, OpenSearch ni Wazuh reales):
loader + lookup -> process_event (Fast Path) -> payload de soc:decisions ->
documento del indexador + mapping -> hash-chain -> alert.data del Active
Response (automático y aprobación manual vía worker/enforcer).
"""
from __future__ import annotations

import importlib
import json
import logging
import sys
from pathlib import Path

import dotenv
import pytest

MOTOR_PATH = str(Path(__file__).resolve().parents[2] / "motor")
sys.path.insert(0, MOTOR_PATH)

import attck_mapping
from attck_mapping import (
    ATTACK_FIELDS,
    AttckMappingLoadError,
    attack_fields,
    get_mapping,
    load_mapping,
    lookup,
)
from opensearch_indexer import INDEX_MAPPINGS, parse_decision
from response.config import ResponseSettings
from response.enforcer import WazuhAPIEnforcer, ar_context, respond_block
from response.schemas import ActionType, EnrichmentResult, ResponseTask
from response.worker import process_task
from response_audit_indexer import (
    GENESIS_HASH,
    chain_document,
    verify_chain,
)

REAL_YAML_ENTRIES = 43  # classification.config real de .139 (v1.1 del YAML)
MSG_ID = "1791250000000-0"

ENTRY_OK = {
    "classtype": "network-scan", "description": "Detection of a Network Scan",
    "tactic_id": "TA0043", "tactic_name": "Reconnaissance",
    "technique_id": "T1595", "technique_name": "Active Scanning", "confidence": "alta",
}


def _write_yaml(tmp_path: Path, entries: list[dict], version: str = "9.9") -> Path:
    import yaml
    path = tmp_path / "classtype_attack.yaml"
    path.write_text(yaml.safe_dump({"version": version, "mappings": entries}), encoding="utf-8")
    return path


# ── Loader ────────────────────────────────────────────────────────────────────

class TestYamlReal:
    def test_el_yaml_del_repo_carga_y_valida(self) -> None:
        mapping = load_mapping()
        assert mapping.version == "1.1"
        assert len(mapping.mappings) == REAL_YAML_ENTRIES

    def test_indice_tiene_nombre_corto_y_descripcion_de_cada_entrada(self) -> None:
        _, index = get_mapping()
        assert len(index) == 2 * REAL_YAML_ENTRIES

    def test_se_carga_una_sola_vez_por_proceso(self, tmp_path, mocker) -> None:
        path = _write_yaml(tmp_path, [ENTRY_OK])
        spy = mocker.spy(attck_mapping, "load_mapping")
        get_mapping.cache_clear()
        try:
            for _ in range(5):
                lookup("network-scan", path)
            assert spy.call_count == 1
        finally:
            get_mapping.cache_clear()


class TestLoaderFallaRuidoso:
    def test_archivo_inexistente(self, tmp_path) -> None:
        with pytest.raises(AttckMappingLoadError, match="no se pudo leer"):
            load_mapping(tmp_path / "no-existe.yaml")

    def test_yaml_invalido(self, tmp_path) -> None:
        path = tmp_path / "roto.yaml"
        path.write_text("mappings: [\n  - classtype: x\n    : :", encoding="utf-8")
        with pytest.raises(AttckMappingLoadError, match="no es YAML válido"):
            load_mapping(path)

    def test_yaml_vacio(self, tmp_path) -> None:
        path = tmp_path / "vacio.yaml"
        path.write_text("", encoding="utf-8")
        with pytest.raises(AttckMappingLoadError, match="vacío"):
            load_mapping(path)

    @pytest.mark.parametrize("override", [
        {"technique_id": "T15"},                    # ID mal formado
        {"tactic_id": "T0043"},                     # táctica sin prefijo TA
        {"tactic_name": None},                      # id sin nombre
        {"technique_id": None},                     # nombre sin id
        {"confidence": "altisima"},                 # fuera del Literal
    ])
    def test_entrada_fuera_de_schema(self, tmp_path, override) -> None:
        path = _write_yaml(tmp_path, [{**ENTRY_OK, **override}])
        with pytest.raises(AttckMappingLoadError, match="schema"):
            load_mapping(path)

    def test_classtype_duplicado(self, tmp_path) -> None:
        path = _write_yaml(tmp_path, [ENTRY_OK, {**ENTRY_OK, "description": "otra"}])
        with pytest.raises(AttckMappingLoadError, match="duplicada"):
            load_mapping(path)

    def test_descripcion_que_choca_con_otra_sin_importar_mayusculas(self, tmp_path) -> None:
        otra = {**ENTRY_OK, "classtype": "otro", "description": ENTRY_OK["description"].upper()}
        path = _write_yaml(tmp_path, [ENTRY_OK, otra])
        with pytest.raises(AttckMappingLoadError, match="duplicada"):
            load_mapping(path)


# ── Lookup ────────────────────────────────────────────────────────────────────

class TestLookup:
    def test_por_nombre_corto(self) -> None:
        entry = lookup("attempted-recon")
        assert (entry.tactic_id, entry.technique_id) == ("TA0043", "T1595")

    def test_por_descripcion_como_la_trae_eve_alert_category(self) -> None:
        assert lookup("Attempted Information Leak").classtype == "attempted-recon"

    def test_sin_distinguir_mayusculas_ni_espacios(self) -> None:
        # En .139 la descripción de web-application-activity empieza en minúscula.
        assert lookup("  ACCESS to a potentially vulnerable web application ").classtype == "web-application-activity"
        assert lookup("Web-Application-Attack").technique_id == "T1190"

    @pytest.mark.parametrize("value", ["", "   ", None, "classtype-que-no-existe"])
    def test_vacio_o_desconocido_devuelve_none(self, value) -> None:
        assert lookup(value) is None


class TestAttackFields:
    def test_match_completo(self) -> None:
        assert attack_fields("web-application-attack") == {
            "attack_tactic_id": "TA0001",
            "attack_tactic_name": "Initial Access",
            "attack_technique_id": "T1190",
            "attack_technique_name": "Exploit Public-Facing Application",
            "attack_confidence": "alta",
            "attack_mapping_version": "1.1",
        }

    def test_entrada_sin_tecnica_se_distingue_de_classtype_desconocido(self) -> None:
        sin_tecnica = attack_fields("Misc Attack")
        assert sin_tecnica["attack_technique_id"] is None
        assert sin_tecnica["attack_confidence"] == "baja"
        assert sin_tecnica["attack_mapping_version"] == "1.1"
        assert attack_fields("desconocido") == dict.fromkeys(ATTACK_FIELDS)

    def test_sin_classtype_todo_none(self) -> None:
        assert attack_fields("") == dict.fromkeys(ATTACK_FIELDS)

    def test_yaml_roto_degrada_a_none_y_loguea_error(self, tmp_path, caplog) -> None:
        broken = tmp_path / "roto.yaml"
        broken.write_text("version: '1'\nmappings: []\n", encoding="utf-8")
        with caplog.at_level(logging.ERROR, logger="motor.attck"):
            assert attack_fields("network-scan", broken) == dict.fromkeys(ATTACK_FIELDS)
        assert "mapeo ATT&CK no disponible" in caplog.text
        get_mapping.cache_clear()


# ── Fast Path: process_event ──────────────────────────────────────────────────

SCORED = {
    "tier": 1, "tier_name": "T1_BAJO", "risk_score": 0.41, "anomaly_score": 0.3,
    "ml_score": 0.45, "decision": "LOG", "classtype_override": False,
    "model_version": "golden4-v7.1",
}
FLOW = {"SERVER_TCP_FLAGS": 2, "OUT_PKTS": 1, "FLOW_DURATION_MILLISECONDS": 10, "L4_DST_PORT": 443}


class _Done:
    def __init__(self, value: dict):
        self._value = value

    def result(self) -> dict:
        return self._value


class _FakePool:
    def submit(self, fn, *args):
        return _Done(dict(SCORED))


@pytest.fixture
def main_mod(monkeypatch, mocker):
    monkeypatch.setenv("REDIS_PASSWORD", "test-pass")
    monkeypatch.setenv("REDIS_HOST", "127.0.0.1")
    monkeypatch.setenv("REDIS_PORT", "1")  # sin Redis real
    monkeypatch.syspath_prepend(MOTOR_PATH)  # hay otro main.py en la raíz del repo
    for mod in ("main", "redis_client", "response.queue", "response.config"):
        sys.modules.pop(mod, None)
    import main
    monkeypatch.setattr(main, "_score_pool", _FakePool())
    monkeypatch.setattr(main, "publish_flow", mocker.MagicMock())
    monkeypatch.setattr(main, "publish_decision", mocker.MagicMock())
    monkeypatch.setattr(main, "enqueue_response_task", mocker.MagicMock())
    return main


class TestProcessEvent:
    def test_classtype_y_attck_en_la_respuesta_y_en_lo_publicado(self, main_mod) -> None:
        resp = main_mod.process_event(FLOW, "trace-attck-0001", "attempted-recon")
        assert resp["classtype"] == "attempted-recon"
        assert resp["attack_tactic_id"] == "TA0043"
        assert resp["attack_technique_id"] == "T1595"
        assert resp["attack_confidence"] == "media"
        published = main_mod.publish_decision.call_args.args[2]
        assert published["attack_technique_id"] == "T1595"
        assert published["classtype"] == "attempted-recon"

    def test_sin_classtype_campos_presentes_en_none(self, main_mod) -> None:
        resp = main_mod.process_event(FLOW, "trace-attck-0002", "")
        assert resp["classtype"] is None
        for field in ATTACK_FIELDS:
            assert field in resp and resp[field] is None

    def test_yaml_roto_no_tumba_el_fast_path(self, main_mod, monkeypatch) -> None:
        def _broken(*_a, **_k):
            raise AttckMappingLoadError("simulado")
        monkeypatch.setattr(attck_mapping, "get_mapping", _broken)
        resp = main_mod.process_event(FLOW, "trace-attck-0003", "attempted-recon")
        assert resp["tier"] == SCORED["tier"]
        assert resp["classtype"] == "attempted-recon"
        assert resp["attack_technique_id"] is None
        main_mod.publish_decision.assert_called_once()


# ── soc:decisions (payload Redis) ─────────────────────────────────────────────

class _CaptureRedis:
    def __init__(self):
        self.added: list[tuple[str, dict]] = []

    def xadd(self, stream, payload, **kw):
        self.added.append((stream, payload))


@pytest.fixture
def redis_client_mod(monkeypatch):
    monkeypatch.setattr(dotenv, "load_dotenv", lambda *a, **k: False)
    monkeypatch.setenv("REDIS_PASSWORD", "test-pass")
    sys.modules.pop("redis_client", None)
    return importlib.import_module("redis_client")


class TestPublishDecision:
    def _decision(self, **extra) -> dict:
        return {"tier": 1, "risk_score": 0.4, "ml_score": 0.4, "anomaly_score": 0.3,
                "decision": "LOG", "latency_ms": 3.2, **extra}

    def test_campos_nuevos_como_string(self, redis_client_mod, monkeypatch) -> None:
        fake = _CaptureRedis()
        monkeypatch.setattr(redis_client_mod, "get_redis", lambda: fake)
        decision = self._decision(classtype="attempted-recon", **attack_fields("attempted-recon"))
        assert redis_client_mod.publish_decision("t-1", FLOW, decision) is True
        stream, payload = fake.added[0]
        assert stream == "soc:decisions"
        assert payload["classtype"] == "attempted-recon"
        assert payload["attack_technique_id"] == "T1595"
        assert all(isinstance(v, str) for v in payload.values())

    def test_sin_match_las_claves_existen_vacias(self, redis_client_mod, monkeypatch) -> None:
        fake = _CaptureRedis()
        monkeypatch.setattr(redis_client_mod, "get_redis", lambda: fake)
        redis_client_mod.publish_decision("t-2", FLOW, self._decision(classtype=None, **attack_fields("")))
        _, payload = fake.added[0]
        assert payload["classtype"] == ""
        for field in ATTACK_FIELDS:
            assert payload[field] == ""


# ── soc-decisions-* (indexador, mapping, hash-chain) ──────────────────────────

def _stream_msg(**extra) -> dict:
    base = {"trace_id": "t-idx", "timestamp": "2026-10-06T00:30:00+00:00", "tier": "1",
            "risk_score": "0.4", "ml_score": "0.4", "anomaly_score": "0.3", "decision": "LOG",
            "L4_DST_PORT": "443", "OUT_PKTS": "1", "DURATION_MS": "10", "SERVER_FLAGS": "2",
            "latency_ms": "3.2"}
    return {**base, **extra}


class TestIndexador:
    def test_parsea_classtype_y_attck(self) -> None:
        fields = {f: v or "" for f, v in attack_fields("network-scan").items()}
        doc = parse_decision(MSG_ID, _stream_msg(classtype="network-scan", **fields))
        assert doc["doc_type"] == "decision"
        assert doc["classtype"] == "network-scan"
        assert doc["attack_technique_id"] == "T1595"
        assert doc["attack_mapping_version"] == "1.1"

    def test_vacio_en_el_stream_queda_null_en_el_documento(self) -> None:
        doc = parse_decision(MSG_ID, _stream_msg(classtype="", **dict.fromkeys(ATTACK_FIELDS, "")))
        assert doc["classtype"] is None
        assert all(doc[f] is None for f in ATTACK_FIELDS)

    def test_mensaje_de_productor_anterior_sin_las_claves(self) -> None:
        doc = parse_decision(MSG_ID, _stream_msg())
        assert doc["doc_type"] == "decision"
        assert doc["classtype"] is None
        assert all(doc[f] is None for f in ATTACK_FIELDS)

    def test_mapping_keyword_para_todos_los_campos_nuevos(self) -> None:
        props = INDEX_MAPPINGS["properties"]
        assert INDEX_MAPPINGS["dynamic"] is False
        for field in ("classtype", *ATTACK_FIELDS):
            assert props[field] == {"type": "keyword"}


class TestHashChainCubreLosCamposNuevos:
    def _doc(self) -> dict:
        fields = {f: v or "" for f, v in attack_fields("attempted-admin").items()}
        content = parse_decision(MSG_ID, _stream_msg(classtype="attempted-admin", **fields))
        return chain_document(content, 1, GENESIS_HASH)

    def test_documento_integro_verifica_incluso_tras_ida_y_vuelta_json(self) -> None:
        doc = json.loads(json.dumps(self._doc()))  # como vuelve en _source
        assert verify_chain([doc]) == []

    @pytest.mark.parametrize("field,value", [
        ("attack_technique_id", "T9999"), ("classtype", "misc-activity"), ("attack_tactic_id", None),
    ])
    def test_alterar_un_campo_attck_rompe_la_cadena(self, field, value) -> None:
        doc = self._doc()
        doc[field] = value
        assert verify_chain([doc]) != []


# ── Wazuh: alert.data del Active Response ─────────────────────────────────────

class TestArContext:
    def test_sin_classtype_solo_trace_id_y_tier(self) -> None:
        assert ar_context("t-1", 3, "") == {"trace_id": "t-1", "tier": "3"}

    def test_tier_desconocido_se_omite(self) -> None:
        assert ar_context("t-1", None) == {"trace_id": "t-1"}

    def test_con_classtype_agrega_attck_como_strings(self) -> None:
        ctx = ar_context("t-1", 3, "web-application-attack")
        assert ctx["classtype"] == "web-application-attack"
        assert ctx["attack_technique_id"] == "T1190"
        assert ctx["attack_tactic_name"] == "Initial Access"
        assert all(isinstance(v, str) for v in ctx.values())

    def test_classtype_sin_tecnica_no_inventa_campos(self) -> None:
        ctx = ar_context("t-1", 3, "misc-attack")
        assert "attack_technique_id" not in ctx and "attack_tactic_id" not in ctx
        assert ctx["attack_confidence"] == "baja"


def _enforce_settings() -> ResponseSettings:
    return ResponseSettings(response_mode="enforce", enforcer_backend="wazuh_api",
                            wazuh_api_user="test-user",
                            wazuh_api_password="test-pass")  # pragma: allowlist secret (credencial ficticia de test)


class TestWazuhAPIEnforcer:
    def _mock_api(self, mocker):
        token = mocker.MagicMock()
        token.json.return_value = {"data": {"token": "tok"}}
        mocker.patch("response.enforcer.httpx.post", return_value=token)
        return mocker.patch("response.enforcer.httpx.put", return_value=mocker.MagicMock())

    def test_contexto_viaja_en_alert_data_junto_a_srcip(self, mocker) -> None:
        put = self._mock_api(mocker)
        ctx = ar_context("t-wz", 3, "attempted-admin")
        enforced, error = WazuhAPIEnforcer(_enforce_settings()).block("1.2.3.4", 3600, ctx)
        assert (enforced, error) == (True, None)
        body = put.call_args.kwargs["json"]
        assert body["command"] == "!firewall-drop"
        assert body["alert"]["data"] == {**ctx, "srcip": "1.2.3.4"}

    def test_el_contexto_no_puede_pisar_srcip(self, mocker) -> None:
        put = self._mock_api(mocker)
        WazuhAPIEnforcer(_enforce_settings()).block("1.2.3.4", 3600, {"srcip": "9.9.9.9", "trace_id": "t"})
        assert put.call_args.kwargs["json"]["alert"]["data"]["srcip"] == "1.2.3.4"

    def test_sin_contexto_mismo_body_que_antes(self, mocker) -> None:
        put = self._mock_api(mocker)
        WazuhAPIEnforcer(_enforce_settings()).block("1.2.3.4", 3600)
        assert put.call_args.kwargs["json"]["alert"] == {"data": {"srcip": "1.2.3.4"}}


class TestRespondBlockPasaElContexto:
    def _run(self, mocker, context):
        rdb = mocker.MagicMock(**{"exists.return_value": 0})
        enforcer = mocker.MagicMock()
        enforcer.name = "wazuh_api"
        enforcer.block.return_value = (True, None)
        result = respond_block("1.2.3.4", _enforce_settings(), rdb, enforcer, "t-rb", context=context)
        return result, enforcer

    def test_contexto_explicito(self, mocker) -> None:
        ctx = ar_context("t-rb", 3, "network-scan")
        result, enforcer = self._run(mocker, ctx)
        assert result.action == ActionType.BLOCK
        assert enforcer.block.call_args.args[2] == ctx

    def test_sin_contexto_manda_al_menos_trace_id(self, mocker) -> None:
        _, enforcer = self._run(mocker, None)
        assert enforcer.block.call_args.args[2] == {"trace_id": "t-rb"}


class TestWorkerArmaElContexto:
    def test_bloqueo_corroborado_lleva_tier_y_attck(self, mocker) -> None:
        settings = ResponseSettings(r1_min_tier=1, r2_min_tier=2,
                                    min_corroborating_sources_for_autoblock=2, response_mode="dry_run")
        mocker.patch("response.worker.enrich", return_value=EnrichmentResult(
            src_ip="1.2.3.5", corroboration_count=2, corroborating_sources=["abuseipdb", "otx"]))
        respond = mocker.patch("response.worker.respond_block", return_value=mocker.MagicMock(
            action=ActionType.BLOCK, enforced=True, reason="bloqueo ejecutado", enforcer="dry_run"))
        task = ResponseTask(trace_id="t-wk", tier=3, risk_score=0.9, src_ip="1.2.3.5",
                            classtype="attempted-recon")
        process_task(task, settings, mocker.MagicMock(**{"get.return_value": None}), mocker.MagicMock())
        ctx = respond.call_args.kwargs["context"]
        assert ctx["trace_id"] == "t-wk" and ctx["tier"] == "3"
        assert ctx["attack_technique_id"] == "T1595"
