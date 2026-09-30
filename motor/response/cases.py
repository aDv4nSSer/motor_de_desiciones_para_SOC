"""
response/cases.py — Apertura de casos desde el worker de respuesta (`.140`).

Mismo esquema y mismas keys de Redis que vigilante/cases.py (que corre en
`.139` para hallazgos de host/FIM) — así dashboard.list_cases() y
update_case_state(), que ya leen soc:cases:*, ven ambos orígenes (red y
host) sin ningún cambio ni duplicación de índice. Se duplica el código (en
vez de importar vigilante.cases desde acá) porque son paquetes de servicios
distintos que corren en hosts distintos — no se acoplan por import directo.

Motor SOC — Tesis UBO.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone

import redis

log = logging.getLogger("response.cases")

CASES_KEY_PREFIX = "soc:cases:"
CASES_INDEX_KEY = "soc:cases:index"


def open_case(kind: str, host: str, detail: dict, rdb: redis.Redis) -> dict:
    """Crea un nuevo caso automático. Mismo formato que vigilante/cases.py:open_case().

    Args:
        kind: tipo de hallazgo, ej. "network_t2_unconfirmed".
        host: origen del hallazgo (acá, típicamente la IP de origen del flujo).
        detail: contexto libre (score, fuentes de corroboración, etc.)
        rdb: cliente Redis ya conectado (worker.py ya mantiene uno).

    Returns:
        El caso creado, con su case_id.
    """
    case_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    case = {
        "case_id": case_id,
        "kind": kind,
        "host": host,
        "detail": detail,
        "state": "abierto",
        "opened_at": now,
        "updated_at": now,
        "history": [{"state": "abierto", "at": now, "note": "Caso creado automáticamente (R1, tier T2)"}],
    }
    try:
        rdb.set(f"{CASES_KEY_PREFIX}{case_id}", json.dumps(case))
        rdb.sadd(CASES_INDEX_KEY, case_id)
    except redis.RedisError as e:
        log.error(f"no se pudo abrir caso automatico para {host}: {e}")
        return case  # se devuelve igual para que el llamador tenga el case_id generado
    return case
