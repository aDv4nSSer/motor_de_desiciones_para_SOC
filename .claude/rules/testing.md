# Estándares de Testing

Un sistema de decisión de seguridad sin tests es indefendible. Cada servicio
tiene cobertura mínima antes de integrarse a develop.

## Estructura de tests por servicio

```
services/
  decision-engine/
    tests/
      unit/
        test_scoring.py          # lógica de re-scoring y tiers
        test_rules_engine.py     # evaluación de rules.yaml → rules_fired + reasoning
        test_risk_accumulation.py # sorted set Redis con decaimiento
        test_hash_chain.py       # prev_hash + hash en soc-decisions
      integration/
        test_fast_path.py        # POST /api/v1/decide end-to-end con Redis mock
        test_enrichment_worker.py # consume stream → produce decisión final
        test_feedback_endpoint.py # POST /api/v1/decisions/{id}/feedback
  historical-context-svc/
    tests/
      unit/
        test_trend_calculation.py # z-score y ratio sobre buckets horarios
        test_recidivism_query.py  # query OpenSearch para T2/T3 últimos 30d
      integration/
        test_context_redis_first.py  # Redis hit → sin llamada a OpenSearch
        test_context_opensearch_fallback.py # Redis frío → OpenSearch → cachear
  threat-intel-svc/
    tests/
      unit/
        test_cache_cascade.py     # L0 → L1 → L2 → API con mocks
        test_circuit_breaker.py   # N fallos → abrir → M minutos → cerrar
        test_normalization.py     # respuesta cruda proveedor → NormalizedTI
        test_negative_cache.py    # resultado limpio/desconocido cacheable
      integration/
        test_enrich_endpoint.py   # GET /api/v1/enrich con providers mockeados
```

## Patrones obligatorios

**Mock de dependencias externas — nunca llamar APIs reales en tests:**

```python
import pytest
from unittest.mock import AsyncMock, patch

@pytest.fixture
def mock_redis():
    with patch("services.context.redis_client") as mock:
        mock.mget = AsyncMock(return_value=[b"45", b"38", b"52"])
        mock.ping = AsyncMock(return_value=True)
        yield mock

@pytest.fixture
def mock_abuseipdb():
    with patch("services.ti.adapters.abuseipdb.httpx.AsyncClient") as mock:
        mock.return_value.__aenter__.return_value.get = AsyncMock(
            return_value=MockResponse({"data": {"abuseConfidenceScore": 92}})
        )
        yield mock
```

**Test de degradación — verificar que el sistema funciona cuando las dependencias fallan:**

```python
async def test_context_svc_degrades_gracefully_on_redis_failure(mock_redis_error):
    """Si Redis falla, el servicio debe caer a OpenSearch sin lanzar excepción al cliente."""
    response = await client.get("/api/v1/context/ip/1.2.3.4",
                                headers={"X-Internal-Key": TEST_KEY,
                                         "X-Trace-Id": "test-trace-001"})
    assert response.status_code == 200
    assert response.json()["source"] == "opensearch"

async def test_decision_continues_when_ti_unavailable(mock_ti_circuit_open):
    """Si TI está con circuito abierto, la decisión se produce igualmente."""
    result = await decide(event_fixture)
    assert result.decision is not None
    assert result.threat_intel.verdict == "unavailable"
```

**Test del trace_id — verificar propagación:**

```python
async def test_trace_id_propagated_to_response():
    trace = "test-trace-abc-123"
    resp = await client.get("/api/v1/context/ip/1.2.3.4",
                            headers={"X-Trace-Id": trace, "X-Internal-Key": TEST_KEY})
    assert resp.headers["X-Trace-Id"] == trace

async def test_trace_id_present_in_decision_document(opensearch_mock):
    trace = "test-trace-xyz-456"
    await process_enrichment_event(event_with_trace_id=trace)
    doc = opensearch_mock.last_indexed_document()
    assert doc["trace_id"] == trace
```

## Cobertura mínima aceptable

| Componente | Cobertura mínima | Prioridad |
|---|---|---|
| Lógica de scoring y tiers | 90% | P0 — no integrar sin esto |
| Motor de reglas (rules.yaml → reasoning) | 90% | P0 |
| Hash chain (prev_hash + hash) | 100% | P0 — auditoría crítica |
| Cascada de caché TI | 85% | P1 |
| Circuit breaker | 85% | P1 |
| Cálculo de trend / z-score | 85% | P1 |
| Health check endpoints | 80% | P2 |

Ejecutar con: `pytest --cov=. --cov-report=term-missing -v`
CI debe fallar si la cobertura de P0 cae por debajo del mínimo.
