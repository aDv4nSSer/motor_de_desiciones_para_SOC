"""
rules/engine.py — Motor de reglas declarativo: evalúa rules.yaml contra el
contexto de una decisión (tier, enriquecimiento, classtype, etc.) y produce
rules_fired[] + reasoning[] para soc-decisions.

Aditivo, no reemplaza nada: la decisión real (tier, bloqueo, aprobación) la
sigue tomando main.py (Fast Path) y response/worker.py (R1/R2) -- esto solo
EXPLICA esa decisión ya tomada con las mismas señales que el worker ya
calculó, igual que SHAP explica el score del modelo. `weight` queda
calculado (rules_total_weight) pero NO alimenta ninguna acción todavía --
ver nota en evaluate().

No hay eval() en ningún punto: las condiciones son datos estructurados
(Condition, ver rules/schemas.py), el evaluador solo las recorre.
"""
from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path
from typing import Any, NamedTuple

import yaml
from pydantic import ValidationError
from rules.schemas import Condition, RuleSet

log = logging.getLogger("rules.engine")

DEFAULT_RULES_PATH = Path(__file__).parent / "rules.yaml"


class RulesLoadError(Exception):
    """rules.yaml falta, no parsea como YAML, o no cumple el schema de
    RuleSet (ids duplicados, condición mal formada, etc.). Se lanza al
    cargar, no se degrada en silencio -- un rules.yaml roto en producción
    debe fallar ruidoso en el arranque del worker, no evaluar como si no
    hubiera reglas."""


def load_rules(path: Path | str = DEFAULT_RULES_PATH) -> RuleSet:
    """Carga y valida rules.yaml. Lanza RulesLoadError con el motivo exacto
    si el archivo falta, no es YAML válido, o no cumple el schema."""
    path = Path(path)
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as e:
        raise RulesLoadError(f"no se pudo leer {path}: {e}") from e
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        raise RulesLoadError(f"{path} no es YAML válido: {e}") from e
    if data is None:
        raise RulesLoadError(f"{path} está vacío")
    try:
        return RuleSet.model_validate(data)
    except ValidationError as e:
        raise RulesLoadError(f"{path} no cumple el schema de reglas: {e}") from e


@lru_cache(maxsize=1)
def get_rules(path: Path | str = DEFAULT_RULES_PATH) -> RuleSet:
    """Carga rules.yaml UNA VEZ por proceso (mismo patrón que el modelo ML
    en main.py:_init_score_worker -- instancia única en memoria, no releer
    el archivo en cada decisión). lru_cache tiene una sola entrada real en
    producción (siempre el mismo DEFAULT_RULES_PATH); el parámetro existe
    para poder inyectar un rules.yaml de prueba en los tests sin pisar el
    caché del real."""
    return load_rules(path)


def _get_field(context: dict[str, Any], field: str) -> Any:
    """Soporta "a.b" como acceso anidado simple (dict-of-dicts), sin eval.
    Campo ausente en cualquier nivel -> None (una condición "eq"/"gt"/etc.
    sobre None siempre da False; "exists" es la única que lo distingue)."""
    value: Any = context
    for part in field.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def _eval_leaf(cond: Condition, context: dict[str, Any]) -> bool:
    actual = _get_field(context, cond.field)  # type: ignore[arg-type]
    if cond.op == "exists":
        return actual is not None
    if actual is None:
        # Ningún otro operador puede ser verdadero contra un campo ausente
        # -- evita falsos "eq con None == None" si `value` también es null.
        return False
    if cond.op == "eq":
        return actual == cond.value
    if cond.op == "ne":
        return actual != cond.value
    if cond.op == "gt":
        return actual > cond.value
    if cond.op == "gte":
        return actual >= cond.value
    if cond.op == "lt":
        return actual < cond.value
    if cond.op == "lte":
        return actual <= cond.value
    if cond.op == "in":
        return actual in cond.value
    if cond.op == "not_in":
        return actual not in cond.value
    if cond.op == "contains":
        return isinstance(actual, (list, tuple, set)) and cond.value in actual
    raise AssertionError(f"operador sin implementar: {cond.op!r}")  # inalcanzable: Condition ya lo valida


def eval_condition(cond: Condition, context: dict[str, Any]) -> bool:
    """Evalúa una Condition (hoja o combinador) contra el contexto. Pura,
    sin side effects -- recursiva sobre all/any/not."""
    if cond.all is not None:
        return all(eval_condition(c, context) for c in cond.all)
    if cond.any is not None:
        return any(eval_condition(c, context) for c in cond.any)
    if cond.not_ is not None:
        return not all(eval_condition(c, context) for c in cond.not_)
    return _eval_leaf(cond, context)


class EvaluationResult(NamedTuple):
    rules_fired: list[str]
    reasoning: list[str]
    total_weight: float


def evaluate(context: dict[str, Any], ruleset: RuleSet | None = None) -> EvaluationResult:
    """Evalúa todas las reglas de `ruleset` (o las de rules.yaml por
    defecto, cacheadas) contra `context` y devuelve las que dispararon.

    Args:
        context: hechos ya calculados de la decisión (tier, risk_score,
            classtype, classtype_override, corroboration_count,
            corroborating_sources, crowdsec_observado, is_safelisted,
            is_stale, otx_available, abuseipdb_available, ...) -- ver
            response/worker.py:_rule_context() para el mapeo real.
        ruleset: set de reglas a evaluar; None usa get_rules() (el
            rules.yaml real, cacheado). Pasar uno explícito en tests para
            no depender del archivo del repo.

    Returns:
        EvaluationResult(rules_fired, reasoning, total_weight). Orden
        estable: el mismo orden en que aparecen en rules.yaml. weight
        queda sumado pero NO se usa para ninguna decisión todavía -- ver
        docstring del módulo.
    """
    rs = ruleset if ruleset is not None else get_rules()
    fired: list[str] = []
    reasoning: list[str] = []
    total_weight = 0.0
    for rule in rs.rules:
        if eval_condition(rule.when, context):
            fired.append(rule.id)
            reasoning.append(rule.text)
            total_weight += rule.weight
    return EvaluationResult(rules_fired=fired, reasoning=reasoning, total_weight=total_weight)
