"""
Motor de reglas declarativo (rules.yaml -> rules_fired[]/reasoning[],
CLAUDE.md "Servicios en construcción"). P0 (testing.md): 90% mínimo.

Cubre:
- schemas.py: Condition exige exactamente hoja (field/op) O combinador
  (all/any/not), nunca ambas ni ninguna; Rule rechaza ids con espacios;
  RuleSet rechaza ids duplicados.
- engine.py: cada operador (eq/ne/gt/gte/lt/lte/in/not_in/contains/exists),
  combinadores anidados, acceso a campo anidado "a.b", campo ausente,
  load_rules con archivo faltante/YAML roto/schema inválido (RulesLoadError
  en los tres casos, nunca una lista vacía silenciosa), evaluate() con
  orden estable y total_weight correcto.
- El rules.yaml REAL del repo carga sin error y un puñado de reglas
  conocidas disparan en los contextos reales que arma worker.py (no solo
  un ruleset sintético) -- valida el archivo end-to-end, no solo el motor.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "motor"))

from rules.engine import (
    DEFAULT_RULES_PATH,
    EvaluationResult,
    RulesLoadError,
    eval_condition,
    evaluate,
    get_rules,
    load_rules,
)
from rules.schemas import Condition, Rule, RuleSet

# ── schemas.py ───────────────────────────────────────────────────────────

class TestCondition:
    def test_hoja_valida(self) -> None:
        c = Condition(field="tier", op="eq", value=3)
        assert c.field == "tier" and c.op == "eq" and c.value == 3

    def test_combinador_all_valido(self) -> None:
        c = Condition(all=[Condition(field="tier", op="eq", value=3)])
        assert c.all is not None and len(c.all) == 1

    def test_not_usa_alias_sin_guion_bajo(self) -> None:
        c = Condition.model_validate({"not": [{"field": "tier", "op": "eq", "value": 0}]})
        assert c.not_ is not None

    def test_hoja_y_combinador_juntos_rechazado(self) -> None:
        with pytest.raises(ValidationError, match="hoja.*combinador|ambas"):
            Condition(field="tier", op="eq", value=3, all=[Condition(field="x", op="eq", value=1)])

    def test_hoja_incompleta_rechazada(self) -> None:
        with pytest.raises(ValidationError):
            Condition(field="tier")  # falta op

    def test_combinador_vacio_rechazado(self) -> None:
        with pytest.raises(ValidationError, match="vacías"):
            Condition(all=[])

    def test_ni_hoja_ni_combinador_rechazado(self) -> None:
        with pytest.raises(ValidationError):
            Condition()

    def test_op_invalido_rechazado(self) -> None:
        with pytest.raises(ValidationError):
            Condition(field="tier", op="equals_maybe", value=3)


class TestRule:
    def test_id_con_espacios_rechazado(self) -> None:
        with pytest.raises(ValidationError, match="espacios"):
            Rule(id="regla con espacio", text="x", when=Condition(field="tier", op="eq", value=1))

    def test_texto_vacio_rechazado(self) -> None:
        with pytest.raises(ValidationError):
            Rule(id="R1", text="", when=Condition(field="tier", op="eq", value=1))

    def test_weight_default_cero(self) -> None:
        r = Rule(id="R1", text="x", when=Condition(field="tier", op="eq", value=1))
        assert r.weight == 0.0


class TestRuleSet:
    def test_ids_duplicados_rechazados(self) -> None:
        cond = Condition(field="tier", op="eq", value=1)
        with pytest.raises(ValidationError, match="duplicados"):
            RuleSet(rules=[Rule(id="R1", text="a", when=cond), Rule(id="R1", text="b", when=cond)])


# ── engine.py: eval_condition ───────────────────────────────────────────

OPERADORES_NUMERICOS = [
    ("eq", 3, 3, True), ("eq", 3, 4, False),
    ("ne", 3, 4, True), ("ne", 3, 3, False),
    ("gt", 3, 2, True), ("gt", 3, 3, False),
    ("gte", 3, 3, True), ("gte", 3, 4, False),
    ("lt", 2, 3, True), ("lt", 3, 3, False),
    ("lte", 3, 3, True), ("lte", 4, 3, False),
]


class TestEvalCondition:
    @pytest.mark.parametrize("op,actual,value,expected", OPERADORES_NUMERICOS)
    def test_operadores_numericos(self, op, actual, value, expected) -> None:
        cond = Condition(field="x", op=op, value=value)
        assert eval_condition(cond, {"x": actual}) is expected

    def test_in(self) -> None:
        cond = Condition(field="classtype", op="in", value=["trojan-activity", "web-application-attack"])
        assert eval_condition(cond, {"classtype": "trojan-activity"}) is True
        assert eval_condition(cond, {"classtype": "misc-activity"}) is False

    def test_not_in(self) -> None:
        cond = Condition(field="classtype", op="not_in", value=["trojan-activity"])
        assert eval_condition(cond, {"classtype": "misc-activity"}) is True

    def test_contains_campo_lista(self) -> None:
        cond = Condition(field="corroborating_sources", op="contains", value="otx")
        assert eval_condition(cond, {"corroborating_sources": ["otx", "abuseipdb"]}) is True
        assert eval_condition(cond, {"corroborating_sources": ["abuseipdb"]}) is False

    def test_contains_sobre_no_lista_da_false(self) -> None:
        cond = Condition(field="x", op="contains", value="otx")
        assert eval_condition(cond, {"x": "otx"}) is False  # string no es la lista que se pide

    def test_exists(self) -> None:
        cond = Condition(field="abuseipdb_score", op="exists", value=None)
        assert eval_condition(cond, {"abuseipdb_score": 0}) is True   # 0 existe, no es None
        assert eval_condition(cond, {"abuseipdb_score": None}) is False
        assert eval_condition(cond, {}) is False

    def test_campo_ausente_distinto_de_exists_da_false(self) -> None:
        cond = Condition(field="x", op="eq", value=3)
        assert eval_condition(cond, {}) is False

    def test_campo_anidado_a_b(self) -> None:
        cond = Condition(field="enrichment.otx_available", op="eq", value=False)
        assert eval_condition(cond, {"enrichment": {"otx_available": False}}) is True
        assert eval_condition(cond, {"enrichment": {"otx_available": True}}) is False
        assert eval_condition(cond, {"enrichment": "no-es-un-dict"}) is False

    def test_all_todas_verdaderas(self) -> None:
        cond = Condition(all=[
            Condition(field="tier", op="eq", value=3),
            Condition(field="is_stale", op="eq", value=False),
        ])
        assert eval_condition(cond, {"tier": 3, "is_stale": False}) is True
        assert eval_condition(cond, {"tier": 3, "is_stale": True}) is False

    def test_any_al_menos_una(self) -> None:
        cond = Condition(any=[
            Condition(field="otx_available", op="eq", value=False),
            Condition(field="abuseipdb_available", op="eq", value=False),
        ])
        assert eval_condition(cond, {"otx_available": True, "abuseipdb_available": False}) is True
        assert eval_condition(cond, {"otx_available": True, "abuseipdb_available": True}) is False

    def test_not_niega_el_bloque(self) -> None:
        cond = Condition.model_validate({"not": [{"field": "is_safelisted", "op": "eq", "value": True}]})
        assert eval_condition(cond, {"is_safelisted": False}) is True
        assert eval_condition(cond, {"is_safelisted": True}) is False

    def test_anidamiento_profundo(self) -> None:
        cond = Condition(all=[
            Condition(field="tier", op="eq", value=3),
            Condition(any=[
                Condition(field="corroborating_sources", op="contains", value="otx"),
                Condition(field="corroborating_sources", op="contains", value="abuseipdb"),
            ]),
        ])
        assert eval_condition(cond, {"tier": 3, "corroborating_sources": ["otx"]}) is True
        assert eval_condition(cond, {"tier": 3, "corroborating_sources": []}) is False


# ── engine.py: load_rules ───────────────────────────────────────────────

class TestLoadRules:
    def test_archivo_inexistente(self, tmp_path) -> None:
        with pytest.raises(RulesLoadError, match="no se pudo leer"):
            load_rules(tmp_path / "no-existe.yaml")

    def test_yaml_invalido(self, tmp_path) -> None:
        p = tmp_path / "roto.yaml"
        p.write_text("rules: [esto: no: es: yaml: valido:::")
        with pytest.raises(RulesLoadError, match="YAML válido"):
            load_rules(p)

    def test_archivo_vacio(self, tmp_path) -> None:
        p = tmp_path / "vacio.yaml"
        p.write_text("")
        with pytest.raises(RulesLoadError, match="vacío"):
            load_rules(p)

    def test_schema_invalido_no_crea_lista_vacia_silenciosa(self, tmp_path) -> None:
        p = tmp_path / "malo.yaml"
        p.write_text(yaml.dump({"rules": [{"id": "R1", "text": "x", "weight": 0, "when": {}}]}))
        with pytest.raises(RulesLoadError, match="schema"):
            load_rules(p)

    def test_archivo_valido_carga_ok(self, tmp_path) -> None:
        p = tmp_path / "ok.yaml"
        p.write_text(yaml.dump({
            "version": "1.0",
            "rules": [{"id": "R1", "text": "x", "weight": 1.5,
                       "when": {"field": "tier", "op": "eq", "value": 3}}],
        }))
        rs = load_rules(p)
        assert len(rs.rules) == 1
        assert rs.rules[0].id == "R1"


# ── engine.py: evaluate ─────────────────────────────────────────────────

def _ruleset(*rules: Rule) -> RuleSet:
    return RuleSet(rules=list(rules))


class TestEvaluate:
    def test_dispara_las_que_matchean_en_orden_del_archivo(self) -> None:
        rs = _ruleset(
            Rule(id="R1", text="uno", weight=1.0, when=Condition(field="tier", op="eq", value=3)),
            Rule(id="R2", text="dos", weight=2.0, when=Condition(field="tier", op="eq", value=99)),
            Rule(id="R3", text="tres", weight=3.0, when=Condition(field="tier", op="eq", value=3)),
        )
        result = evaluate({"tier": 3}, rs)
        assert result == EvaluationResult(
            rules_fired=["R1", "R3"], reasoning=["uno", "tres"], total_weight=4.0,
        )

    def test_ninguna_dispara(self) -> None:
        rs = _ruleset(Rule(id="R1", text="x", when=Condition(field="tier", op="eq", value=99)))
        result = evaluate({"tier": 3}, rs)
        assert result == EvaluationResult(rules_fired=[], reasoning=[], total_weight=0.0)

    def test_ruleset_vacio(self) -> None:
        result = evaluate({"tier": 3}, RuleSet(rules=[]))
        assert result == EvaluationResult(rules_fired=[], reasoning=[], total_weight=0.0)


# ── rules.yaml real del repo ────────────────────────────────────────────

class TestRulesYamlReal:
    def test_carga_sin_error(self) -> None:
        rs = load_rules(DEFAULT_RULES_PATH)
        assert len(rs.rules) == 11

    def test_get_rules_cachea_la_misma_instancia(self) -> None:
        """get_rules() no debe releer el archivo en cada llamada (mismo
        patrón que la carga del modelo ML, una sola vez por proceso)."""
        get_rules.cache_clear()
        a = get_rules(DEFAULT_RULES_PATH)
        b = get_rules(DEFAULT_RULES_PATH)
        assert a is b

    def test_t3_por_classtype_override(self) -> None:
        """Contexto real que arma worker.py cuando Suricata fuerza T3 por
        classtype (ver main.py:T3_CLASSTYPES)."""
        rs = load_rules(DEFAULT_RULES_PATH)
        result = evaluate({
            "tier": 3, "classtype_override": True, "corroboration_count": 1,
            "is_stale": False, "is_safelisted": False,
        }, rs)
        assert "R001_classtype_override_t3" in result.rules_fired
        assert "R002_t3_score_ml" not in result.rules_fired

    def test_t3_corroboracion_insuficiente_matchea_rama_de_aprobacion(self) -> None:
        """Mismo contexto que la rama "corroboración insuficiente" de
        worker.py:process_task (requires_approval=True, N1)."""
        rs = load_rules(DEFAULT_RULES_PATH)
        result = evaluate({
            "tier": 3, "classtype_override": False, "corroboration_count": 1,
            "is_stale": False, "is_safelisted": False,
        }, rs)
        assert "R002_t3_score_ml" in result.rules_fired
        assert "R007_corroboracion_insuficiente_t3" in result.rules_fired
        assert "R008_corroboracion_suficiente_t3" not in result.rules_fired

    def test_t3_corroboracion_suficiente_matchea_rama_de_bloqueo(self) -> None:
        rs = load_rules(DEFAULT_RULES_PATH)
        result = evaluate({
            "tier": 3, "classtype_override": False, "corroboration_count": 2,
            "corroborating_sources": ["otx", "abuseipdb"],
            "is_stale": False, "is_safelisted": False,
        }, rs)
        assert "R008_corroboracion_suficiente_t3" in result.rules_fired
        assert "R004_corroborado_otx" in result.rules_fired
        assert "R005_corroborado_abuseipdb" in result.rules_fired
        assert "R007_corroboracion_insuficiente_t3" not in result.rules_fired

    def test_safelist_gana_sobre_corroboracion_insuficiente(self) -> None:
        """R007 exige is_safelisted=False a propósito -- una IP de infra
        propia no debe reportar "corroboración insuficiente" como si fuera
        a quedar pendiente de aprobación (worker.py la salta directo)."""
        rs = load_rules(DEFAULT_RULES_PATH)
        result = evaluate({
            "tier": 3, "classtype_override": False, "corroboration_count": 0,
            "is_stale": False, "is_safelisted": True,
        }, rs)
        assert "R009_safelisted" in result.rules_fired
        assert "R007_corroboracion_insuficiente_t3" not in result.rules_fired

    def test_ti_no_disponible(self) -> None:
        rs = load_rules(DEFAULT_RULES_PATH)
        result = evaluate({"tier": 2, "otx_available": False, "abuseipdb_available": True}, rs)
        assert "R011_ti_no_disponible" in result.rules_fired
