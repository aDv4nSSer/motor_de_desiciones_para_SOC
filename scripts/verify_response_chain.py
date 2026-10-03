#!/usr/bin/env python3
"""
verify_response_chain.py — Verifica la integridad del hash-chain de soc-responses (H39).

Recorre todos los documentos de soc-responses-* en orden de chain_seq
(search_after, páginas de 1000) y reporta el primer documento alterado, los
saltos de secuencia y los prev_hash que no apuntan al anterior. Solo lectura.

Uso (en .140, desde motor/ para tomar el .env):
    python3 ../scripts/verify_response_chain.py

Código de salida: 0 si la cadena está íntegra, 1 si hay problemas.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "motor"))

from response_audit_indexer import (  # noqa: E402
    INDEX_PATTERN,
    AuditIndexerSettings,
    OpenSearchClient,
    verify_chain,
)

PAGE = 1000
MAX_REPORTED = 20


def main() -> int:
    client = OpenSearchClient(AuditIndexerSettings())
    problems: list[str] = []
    total, last, first_seq = 0, None, None
    search_after = None
    while True:
        body = {"size": PAGE, "sort": [{"chain_seq": "asc"}]}
        if search_after is not None:
            body["search_after"] = search_after
        r = client.request("POST", f"/{INDEX_PATTERN}/_search", body)
        if r.status_code == 404:
            break
        r.raise_for_status()
        hits = r.json()["hits"]["hits"]
        if not hits:
            break
        docs = [h["_source"] for h in hits]
        if first_seq is None:
            first_seq = docs[0].get("chain_seq")
        # El último de la página anterior entra como ancla para chequear el empalme.
        checked = verify_chain(([last] if last else []) + docs)
        problems.extend(checked)
        total += len(docs)
        last = docs[-1]
        search_after = hits[-1]["sort"]
    if total == 0:
        print("soc-responses: sin documentos")
        return 0
    print(f"documentos verificados: {total} | chain_seq {first_seq} -> {last.get('chain_seq')}")
    if first_seq != 1:
        print(f"nota: la cadena empieza en chain_seq {first_seq} (índices más viejos borrados por retención)")
    if problems:
        print(f"PROBLEMAS: {len(problems)}")
        for p in problems[:MAX_REPORTED]:
            print("  -", p)
        return 1
    print("cadena íntegra")
    return 0


if __name__ == "__main__":
    sys.exit(main())
