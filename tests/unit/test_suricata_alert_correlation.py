"""
H53: grupo `signature` del score de corroboración -- correlación del worker
con suricata-alerts-* (response/enrichment.py:lookup_suricata_alert).

OpenSearch siempre mockeado (httpx.MockTransport), nunca real (testing.md).
Cubre: DSL (3-tupla en ambos sentidos, ventana asimétrica, campos .keyword),
match T3 + ATT&CK -> signature 1.0, match no crítico -> 0.3, sin match ->
signature no disponible, timeout/error -> "unavailable" sin lanzar con
WARNING y cooldown, entrada inválida -> "skipped", y la integración con
process_task hasta el documento de soc-responses (el ResponseRecord del
worker va a soc-responses-*, no a soc-decisions -- H52).
"""
from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

from constants import (
    ALERT_CORRELATION_LOOKAHEAD_SECONDS,
    ALERT_CORRELATION_LOOKBACK_SECONDS,
    ALERT_LOOKUP_FAILURE_COOLDOWN_SECONDS,
)
from response import enrichment
from response.config import ResponseSettings
from response.enrichment import build_alert_query, lookup_suricata_alert
from response.schemas import ActionType, BlockResult, EnrichmentResult, ResponseTask
from response.worker import process_task
from response_audit_indexer import build_content
from scoring.corroboration import compute_corroboration

SRC, DST, PORT = "91.92.42.88", "200.54.12.139", 443
TS = 1_791_400_000.0


@pytest.fixture(autouse=True)
def _reset_cooldown():
    enrichment._alerts_unavailable_until = 0.0
    yield
    enrichment._alerts_unavailable_until = 0.0


def _settings(**kw) -> ResponseSettings:
    base = {"r1_min_tier": 2, "r2_min_tier": 3, "response_mode": "dry_run"}
    base.update(kw)
    return ResponseSettings(**base)


def _client(handler) -> httpx.Client:
    return httpx.Client(base_url="https://os.test", transport=httpx.MockTransport(handler))


def _hits(*sources) -> httpx.Response:
    return httpx.Response(200, json={"hits": {"hits": [{"_source": s} for s in sources]}})


def _alert(category: str) -> dict:
    return {"category": category, "signature": "ET prueba", "signature_id": 2500034,
            "severity": 1, "timestamp": "2026-10-07T19:20:15.858922Z"}


def _signature_group(match):
    result = compute_corroboration(
        risk_score=0.83,
        classtype=match.classtype if match else "",
        classtype_override=match.classtype_override if match else False,
        attack_mapped=match.attack_mapped if match else False,
        enrichment=None, settings=_settings(),
    )
    return next(g for g in result.groups if g.name == "signature")


class TestQuery:
    def test_tres_tupla_en_ambos_sentidos_con_ventana_asimetrica(self) -> None:
        q = build_alert_query(SRC, DST, PORT, TS)
        rng = q["query"]["bool"]["filter"][0]["range"]["timestamp"]
        assert rng["gte"] == int((TS - ALERT_CORRELATION_LOOKBACK_SECONDS) * 1000)
        assert rng["lte"] == int((TS + ALERT_CORRELATION_LOOKAHEAD_SECONDS) * 1000)
        assert ALERT_CORRELATION_LOOKBACK_SECONDS > ALERT_CORRELATION_LOOKAHEAD_SECONDS
        ida, vuelta = (b["bool"]["filter"] for b in q["query"]["bool"]["should"])
        assert {"term": {"src_ip.keyword": SRC}} in ida and {"term": {"dest_port": PORT}} in ida
        assert {"term": {"src_ip.keyword": DST}} in vuelta and {"term": {"src_port": PORT}} in vuelta
        assert q["query"]["bool"]["minimum_should_match"] == 1
        assert q["sort"][0] == {"severity": {"order": "asc"}}

    def test_entrada_invalida_no_consulta(self) -> None:
        calls = []
        client = _client(lambda r: calls.append(r) or _hits())
        for src, dst, port in (("no-es-ip", DST, PORT), (SRC, None, PORT), (SRC, DST, 70000)):
            assert lookup_suricata_alert(src, dst, port, TS, _settings(), client=client).status == "skipped"
        assert calls == []


class TestLookup:
    def test_match_t3_con_attck_da_signature_1(self) -> None:
        sent = {}

        def handler(request):
            sent["path"] = request.url.path
            sent["body"] = json.loads(request.content)
            return _hits(_alert("A Network Trojan was detected"))

        res = lookup_suricata_alert(SRC, DST, PORT, TS, _settings(), client=_client(handler))

        assert sent["path"] == "/suricata-alerts-*/_search"
        assert res.status == "match"
        assert res.match.classtype == "trojan-activity"
        assert res.match.classtype_override is True
        assert res.match.attack_mapped is True and res.match.attack_technique_id == "T1071"
        g = _signature_group(res.match)
        assert g.available is True and g.score == 1.0

    def test_match_no_critico_da_signature_0_3(self) -> None:
        res = lookup_suricata_alert(SRC, DST, PORT, TS, _settings(),
                                    client=_client(lambda r: _hits(_alert("Misc Attack"))))
        assert res.status == "match"
        assert res.match.classtype == "misc-attack"
        assert res.match.classtype_override is False and res.match.attack_mapped is False
        g = _signature_group(res.match)
        assert g.available is True and g.score == 0.3

    def test_categoria_desconocida_queda_en_minuscula(self) -> None:
        res = lookup_suricata_alert(SRC, DST, PORT, TS, _settings(),
                                    client=_client(lambda r: _hits(_alert("Algo Nuevo"))))
        assert res.match.classtype == "algo nuevo"
        assert res.match.attack_mapped is False

    def test_sin_match_signature_no_disponible(self) -> None:
        res = lookup_suricata_alert(SRC, DST, PORT, TS, _settings(), client=_client(lambda r: _hits()))
        assert res.status == "no_match" and res.match is None
        assert _signature_group(None).available is False

    @pytest.mark.parametrize("failure", [
        lambda r: (_ for _ in ()).throw(httpx.ReadTimeout("lento", request=r)),
        lambda r: (_ for _ in ()).throw(httpx.ConnectError("caído", request=r)),
        lambda r: httpx.Response(503, json={}),
        lambda r: httpx.Response(200, content=b"no es json"),
    ], ids=["timeout", "connect", "http_503", "json_invalido"])
    def test_error_no_lanza_degrada_y_activa_cooldown(self, caplog, failure) -> None:
        calls = []

        def handler(request):
            calls.append(request)
            return failure(request)

        client = _client(handler)
        with caplog.at_level(logging.WARNING, logger="response.r1"):
            res = lookup_suricata_alert(SRC, DST, PORT, TS, _settings(), client=client, now=1000.0)
        assert res.status == "unavailable" and res.match is None
        assert any("alert_lookup_unavailable" in r.getMessage() for r in caplog.records)
        # Durante el cooldown no se vuelve a consultar...
        again = lookup_suricata_alert(SRC, DST, PORT, TS, _settings(), client=client, now=1001.0)
        assert again.status == "unavailable" and len(calls) == 1
        # ...y pasado el cooldown, sí.
        lookup_suricata_alert(SRC, DST, PORT, TS, _settings(), client=client,
                              now=1000.0 + ALERT_LOOKUP_FAILURE_COOLDOWN_SECONDS + 1)
        assert len(calls) == 2


class TestIntegracionWorker:
    def _process(self, mocker, handler, tier=3):
        settings = _settings()
        rdb = mocker.MagicMock(**{"get.return_value": None})
        rdb.pipeline.return_value.execute.return_value = [0, 1, 0, 0, True]
        mocker.patch("response.worker.enrich", return_value=EnrichmentResult(
            src_ip=SRC, otx_available=True, otx_pulse_count=24, abuseipdb_available=False,
            corroboration_count=1, corroborating_sources=["otx"]))
        mocker.patch("response.worker.create_pending_approval")
        mocker.patch("response.worker.open_case", return_value={"case_id": "c-1"})
        respond_block = mocker.patch("response.worker.respond_block", return_value=BlockResult(
            src_ip=SRC, action=ActionType.BLOCK, enforced=True, enforcer="dry_run"))
        mocker.patch("response.enrichment._get_alerts_client", return_value=_client(handler))
        task = ResponseTask(trace_id="trace-sig-1", tier=tier, risk_score=0.83, src_ip=SRC,
                            dst_ip=DST, L4_DST_PORT=PORT, ts=time.time() - 60)
        record = process_task(task, settings, rdb, mocker.MagicMock(name="dry_run"))
        (_stream, fields), _ = rdb.xadd.call_args
        return record, json.loads(fields["data"]), respond_block

    def test_alerta_correlacionada_llega_a_soc_responses_con_el_bloque(self, mocker) -> None:
        record, audited, respond_block = self._process(
            mocker, lambda r: _hits(_alert("Attempted Administrator Privilege Gain")))

        assert record.alert_lookup == "match"
        assert record.correlated_alert["classtype"] == "attempted-admin"
        sig = next(g for g in record.corroboration_groups if g["name"] == "signature")
        assert sig["available"] is True and sig["score"] == 1.0
        # La decisión real no la ve: sigue pendiente de aprobación (count=1).
        assert record.block.action == ActionType.BLOCK_PENDING_APPROVAL
        respond_block.assert_not_called()

        doc = build_content("1791400000000-0", {"data": json.dumps(audited)})
        assert doc["correlated_classtype"] == "attempted-admin"
        assert doc["correlated_attack_technique_id"] == "T1068"
        assert doc["alert_lookup"] == "match"
        assert doc["corroboration_band"] == record.corroboration_band
        assert "signature" in doc["corroboration_groups_available"]
        assert doc["payload"]["correlated_alert"]["category"] == "Attempted Administrator Privilege Gain"

    def test_t2_no_consulta_opensearch(self, mocker) -> None:
        calls = []
        record, audited, _ = self._process(mocker, lambda r: calls.append(r) or _hits(), tier=2)
        assert calls == []
        assert record.alert_lookup == ""
        doc = build_content("1791400000000-0", {"data": json.dumps(audited)})
        assert "correlated_classtype" not in doc and "alert_lookup" not in doc

    def test_opensearch_caido_no_cambia_la_decision(self, mocker) -> None:
        def down(request):
            raise httpx.ConnectError("caído", request=request)

        record, _, _ = self._process(mocker, down)
        assert record.alert_lookup == "unavailable"
        assert record.block.action == ActionType.BLOCK_PENDING_APPROVAL
        assert record.corroboration_band != ""
