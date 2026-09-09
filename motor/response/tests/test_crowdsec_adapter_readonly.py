"""
response/tests/test_crowdsec_adapter_readonly.py — H37: evidencia
automatizada de que crowdsec_adapter.py es SOLO LECTURA.

No es la promesa de un docstring: análisis estático real del archivo
fuente (texto + AST), verificando que no importa ni llama a subprocess,
os.system/os.popen, ni ningún binario de firewall (iptables/nftables/ufw/
firewall-cmd). Si en el futuro alguien agrega una de estas llamadas, este
test debe fallar.

Corre con pytest si está disponible (`pytest test_crowdsec_adapter_readonly.py`)
o standalone (`python3 test_crowdsec_adapter_readonly.py`) — no depende de
pytest estar instalado, a propósito, ya que no está instalado hoy en .140.
"""
import ast
import io
import re
import tokenize
from pathlib import Path

ADAPTER_PATH = Path(__file__).parent.parent / "crowdsec_adapter.py"

FORBIDDEN_IMPORTS = {"subprocess", "os"}
FORBIDDEN_CALLS = {"system", "popen", "spawnl", "spawnv", "exec", "execl", "execv"}
FORBIDDEN_TEXT_PATTERNS = [
    r"\biptables\b", r"\bnftables\b", r"\bnft\b", r"\bufw\b",
    r"\bfirewall-cmd\b", r"subprocess\.", r"os\.system", r"os\.popen",
]


def _code_only(source: str) -> str:
    """Descarta comentarios y strings (docstrings incluidos) del código
    fuente -- el chequeo de texto prohibido debe mirar código real, no la
    explicación en prosa de por qué el módulo NO llama a esas cosas."""
    out = []
    tokens = tokenize.generate_tokens(io.StringIO(source).readline)
    for tok in tokens:
        if tok.type in (tokenize.COMMENT, tokenize.STRING):
            continue
        out.append(tok.string)
    return " ".join(out)


def test_crowdsec_adapter_never_calls_firewall_or_subprocess():
    source = ADAPTER_PATH.read_text()
    code_only = _code_only(source)

    # 1) Análisis de texto sobre CODIGO real (sin comentarios/docstrings) --
    #    atrapa cualquier mención literal en el código ejecutable. Se
    #    excluyen comentarios/strings a propósito: el propio docstring del
    #    módulo explica, en prosa, por qué NO se llama a estos binarios --
    #    esa explicación menciona las palabras prohibidas sin ser una
    #    llamada real, y no debe hacer fallar el test.
    for pattern in FORBIDDEN_TEXT_PATTERNS:
        assert not re.search(pattern, code_only), (
            f"crowdsec_adapter.py contiene el patrón prohibido '{pattern}' en "
            "código real (no en un comentario/docstring) -- este módulo debe "
            "ser SOLO LECTURA, sin ningún mecanismo de bloqueo propio (ver "
            "H37 en docs/BITACORA_TECNICA.md)."
        )

    # 2) Análisis AST -- atrapa imports reales de subprocess/os, y cualquier
    #    llamada a una función cuyo nombre coincida con las prohibidas
    #    (system/popen/exec*), sin importar de qué módulo venga.
    tree = ast.parse(source, filename=str(ADAPTER_PATH))

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] not in FORBIDDEN_IMPORTS, (
                    f"crowdsec_adapter.py importa '{alias.name}' -- prohibido, "
                    "este módulo debe ser SOLO LECTURA."
                )
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] not in FORBIDDEN_IMPORTS, (
                f"crowdsec_adapter.py importa desde '{node.module}' -- prohibido."
            )
        elif isinstance(node, ast.Call):
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else (
                func.id if isinstance(func, ast.Name) else None
            )
            assert name not in FORBIDDEN_CALLS, (
                f"crowdsec_adapter.py llama a una función prohibida "
                f"('{name}') -- este módulo debe ser SOLO LECTURA."
            )


def test_crowdsec_adapter_has_no_block_action_exports():
    """Confirma que el módulo no expone ninguna función con nombre sugestivo
    de bloqueo (block/ban/enforce/drop/firewall) -- refuerzo del contrato de
    "solo lectura" a nivel de interfaz pública, no solo de implementación."""
    source = ADAPTER_PATH.read_text()
    tree = ast.parse(source, filename=str(ADAPTER_PATH))
    suspicious = {"block", "ban", "enforce", "drop", "firewall"}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            lname = node.name.lower()
            assert not any(word in lname for word in suspicious), (
                f"crowdsec_adapter.py define una función con nombre "
                f"sugestivo de bloqueo ('{node.name}') -- este módulo debe "
                "exponer solo lectura; cualquier acción de bloqueo va en "
                "enforcer.py (R2), nunca acá."
            )


if __name__ == "__main__":
    test_crowdsec_adapter_never_calls_firewall_or_subprocess()
    test_crowdsec_adapter_has_no_block_action_exports()
    print("OK: crowdsec_adapter.py confirmado como solo-lectura (sin subprocess/os.system/binarios de firewall/funciones de bloqueo).")
