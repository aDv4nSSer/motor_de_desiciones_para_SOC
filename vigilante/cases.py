"""
cases.py -- Gestion de casos abiertos por acciones de alto impacto
(cuarentena de archivos, a futuro aislamiento de host).

Persiste en Redis (estado operable, consultado por el dashboard) y en
OpenSearch (auditoria permanente). Motor SOC -- Tesis UBO.
"""
import json
import os
import time
import uuid
from datetime import datetime, timezone

import redis

REDIS_HOST = os.environ.get("REDIS_HOST", "200.54.12.140")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD", "")

CASES_KEY_PREFIX = "soc:cases:"
CASES_INDEX_KEY = "soc:cases:index"  # set con todos los case_id, para listarlos

VALID_STATES = {"abierto", "en_investigacion", "cerrado_confirmado", "cerrado_falso_positivo"}

_client: "redis.Redis | None" = None


def _get_redis() -> redis.Redis:
    global _client
    if _client is None:
        _client = redis.Redis(
            host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD,
            decode_responses=True, socket_timeout=5, socket_connect_timeout=5,
        )
    return _client


def open_case(kind: str, host: str, detail: dict) -> dict:
    """
    Crea un nuevo caso. kind = tipo de accion (ej. 'quarantine_file').
    host = donde ocurrio. detail = contexto libre (archivo, IP, etc.)
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
        "history": [{"state": "abierto", "at": now, "note": "Caso creado automaticamente"}],
    }
    r = _get_redis()
    r.set(f"{CASES_KEY_PREFIX}{case_id}", json.dumps(case))
    r.sadd(CASES_INDEX_KEY, case_id)
    return case


def update_case_state(case_id: str, new_state: str, note: str = "") -> dict | None:
    if new_state not in VALID_STATES:
        raise ValueError(f"Estado invalido: {new_state}")
    r = _get_redis()
    raw = r.get(f"{CASES_KEY_PREFIX}{case_id}")
    if raw is None:
        return None
    case = json.loads(raw)
    now = datetime.now(timezone.utc).isoformat()
    case["state"] = new_state
    case["updated_at"] = now
    case["history"].append({"state": new_state, "at": now, "note": note})
    r.set(f"{CASES_KEY_PREFIX}{case_id}", json.dumps(case))
    return case


def get_case(case_id: str) -> dict | None:
    r = _get_redis()
    raw = r.get(f"{CASES_KEY_PREFIX}{case_id}")
    return json.loads(raw) if raw else None


def list_cases(only_open: bool = False) -> list[dict]:
    r = _get_redis()
    ids = r.smembers(CASES_INDEX_KEY)
    cases = []
    for cid in ids:
        raw = r.get(f"{CASES_KEY_PREFIX}{cid}")
        if raw:
            case = json.loads(raw)
            if not only_open or case["state"] in ("abierto", "en_investigacion"):
                cases.append(case)
    cases.sort(key=lambda c: c["opened_at"], reverse=True)
    return cases
