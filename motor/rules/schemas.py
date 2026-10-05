"""
rules/schemas.py — Contrato de datos de una regla declarativa de rules.yaml.

`when` es un árbol de condiciones ESTRUCTURADAS (dicts con field/op/value,
combinadas con all/any/not), nunca un string que se evalúa -- no hay eval()
ni expresión Python libre en ningún punto de este módulo. Un YAML de reglas
es, en los hechos, entrada externa (lo puede tocar cualquiera con acceso al
repo, y eventualmente podría venir de un endpoint de administración); tratarlo
como código ejecutable sería la misma clase de problema que un `requests`
síncrono o un `==` para comparar API keys -- evitable desde el diseño, no
parcheable después. Ver motor/rules/engine.py para el evaluador.
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

# Operadores soportados en una condición hoja. "in"/"not_in": el valor del
# campo está (o no) dentro de `value` (una lista) -- ej. classtype in
# [...]. "contains": `value` está dentro del campo (el campo es una lista)
# -- ej. "otx" contains-en corroborating_sources. "exists": el campo está
# presente en el contexto y no es None, sin mirar `value`.
ConditionOp = Literal["eq", "ne", "gt", "gte", "lt", "lte", "in", "not_in", "contains", "exists"]


class Condition(BaseModel):
    """Una condición hoja (field/op/value) o un combinador (all/any/not)
    sobre una lista de sub-condiciones. Exactamente una de las dos formas
    por nodo -- se valida en model_validator, no se asume."""
    field: str | None = None
    op: ConditionOp | None = None
    value: Any = None
    all: list[Condition] | None = None
    any: list[Condition] | None = None
    not_: list[Condition] | None = Field(default=None, alias="not")

    model_config = {"populate_by_name": True}

    @model_validator(mode="after")
    def _exactamente_una_forma(self) -> Condition:
        es_hoja = self.field is not None or self.op is not None
        combinadores = [c for c in (self.all, self.any, self.not_) if c is not None]
        if es_hoja and combinadores:
            raise ValueError("una condición es hoja (field/op) O combinador (all/any/not), no ambas")
        if es_hoja and (self.field is None or self.op is None):
            raise ValueError("una condición hoja necesita field Y op")
        if not es_hoja and len(combinadores) != 1:
            raise ValueError("una condición combinador necesita exactamente una de: all, any, not")
        if not es_hoja and not combinadores[0]:
            raise ValueError("all/any/not no pueden ser listas vacías")
        return self


Condition.model_rebuild()


class Rule(BaseModel):
    """Una regla de rules.yaml: {id, when, text, weight}."""
    id: str = Field(..., min_length=1)
    text: str = Field(..., min_length=1)
    weight: float = 0.0
    when: Condition

    @field_validator("id")
    @classmethod
    def _id_sin_espacios(cls, v: str) -> str:
        if " " in v:
            raise ValueError(f"id de regla no puede tener espacios: {v!r}")
        return v


class RuleSet(BaseModel):
    """rules.yaml completo: version + lista de reglas, con IDs únicos."""
    version: str = "1.0"
    rules: list[Rule] = Field(default_factory=list)

    @model_validator(mode="after")
    def _ids_unicos(self) -> RuleSet:
        ids = [r.id for r in self.rules]
        dupes = {i for i in ids if ids.count(i) > 1}
        if dupes:
            raise ValueError(f"ids de regla duplicados en rules.yaml: {sorted(dupes)}")
        return self
