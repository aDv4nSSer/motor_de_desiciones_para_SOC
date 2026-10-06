"""
attck_mapping.py — Lookup en memoria de classtype de Suricata -> MITRE ATT&CK
(Enterprise), a partir de motor/classtype_attack.yaml.

Vive al lado del YAML y no dentro de motor/rules/ a propósito: rules/ es el
motor de EXPLICACIÓN del worker (rules.yaml -> rules_fired/reasoning), y
esto es dato de referencia que consumen dos procesos distintos -- el Fast
Path (main.py:process_event, para soc-decisions) y R2 (response/enforcer,
para el contexto que viaja en el Active Response de Wazuh). Ninguno de los
dos depende del motor de reglas.

Mismo patrón que rules/engine.py:get_rules(): se carga UNA vez por proceso
(lru_cache), falla ruidoso al cargar si el YAML está roto (main.py lo carga
en el lifespan, así un YAML inválido impide arrancar en vez de degradar en
silencio) y nunca se relee por request. El lookup es un dict.get en memoria:
cero IO en el Fast Path.

El lookup acepta el nombre corto (lo que Suricata pondría en el header
X-Suricata-Classtype, ej. "attempted-recon") Y la descripción de
classification.config (lo que eve.json trae en alert.category, ej.
"Attempted Information Leak" -- verificado en suricata-alerts-* de .140 el
5-oct-2026, H50). Ambos sin distinguir mayúsculas: en .139 la descripción
de web-application-activity empieza en minúscula y en upstream no.

Estado real (H50): en producción el classtype NO llega hoy al motor --
Vector solo manda los eventos flow a /decide, sin header ni flow_id -- así
que en tráfico real el lookup devuelve vacío hasta que exista esa fuente.
"""
from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, ValidationError, model_validator

log = logging.getLogger("motor.attck")

DEFAULT_MAPPING_PATH = Path(__file__).parent / "classtype_attack.yaml"

# IDs de ATT&CK Enterprise: tácticas TA0000, técnicas T0000 o T0000.000.
TACTIC_ID_PATTERN = r"^TA\d{4}$"
TECHNIQUE_ID_PATTERN = r"^T\d{4}(\.\d{3})?$"

# Campos planos que agrega una decisión (soc:decisions -> soc-decisions-*) y
# el Active Response de Wazuh. Un único lugar para los nombres: el payload
# Redis, el parseo del indexador y el mapping del índice los leen de acá.
ATTACK_FIELDS: tuple[str, ...] = (
    "attack_tactic_id",
    "attack_tactic_name",
    "attack_technique_id",
    "attack_technique_name",
    "attack_confidence",
    "attack_mapping_version",
)


class AttckMappingLoadError(Exception):
    """classtype_attack.yaml falta, no es YAML válido o no cumple el schema.
    Se lanza al cargar, nunca se degrada en silencio a "sin mapeo"."""


class AttckEntry(BaseModel):
    """Una entrada de classtype_attack.yaml."""
    classtype: str = Field(..., min_length=1)
    description: str = Field(..., min_length=1)
    tactic_id: str | None = Field(default=None, pattern=TACTIC_ID_PATTERN)
    tactic_name: str | None = None
    technique_id: str | None = Field(default=None, pattern=TECHNIQUE_ID_PATTERN)
    technique_name: str | None = None
    confidence: Literal["alta", "media", "baja"]
    notes: str | None = None

    @model_validator(mode="after")
    def _id_y_nombre_juntos(self) -> AttckEntry:
        if (self.tactic_id is None) != (self.tactic_name is None):
            raise ValueError(f"{self.classtype}: tactic_id y tactic_name van juntos (ambos o ninguno)")
        if (self.technique_id is None) != (self.technique_name is None):
            raise ValueError(f"{self.classtype}: technique_id y technique_name van juntos (ambos o ninguno)")
        return self


class AttckMapping(BaseModel):
    """classtype_attack.yaml completo, con nombres cortos y descripciones
    únicos (sin distinguir mayúsculas) -- si no, el lookup sería ambiguo."""
    version: str
    updated: str | None = None
    source_classification_config: str | None = None
    mappings: list[AttckEntry] = Field(..., min_length=1)

    @model_validator(mode="after")
    def _claves_unicas(self) -> AttckMapping:
        seen: set[str] = set()
        for entry in self.mappings:
            for key in (entry.classtype.lower(), entry.description.lower()):
                if key in seen:
                    raise ValueError(f"clave de lookup duplicada en classtype_attack.yaml: {key!r}")
                seen.add(key)
        return self

    def build_index(self) -> dict[str, AttckEntry]:
        """Índice de lookup: nombre corto y descripción en minúscula -> entrada.

        Returns:
            Diccionario con 2 claves por entrada (unicidad ya validada).
        """
        index: dict[str, AttckEntry] = {}
        for entry in self.mappings:
            index[entry.classtype.lower()] = entry
            index[entry.description.lower()] = entry
        return index


def load_mapping(path: Path | str = DEFAULT_MAPPING_PATH) -> AttckMapping:
    """Carga y valida classtype_attack.yaml.

    Args:
        path: ruta del YAML; por defecto el del repo, al lado de este módulo.

    Returns:
        El mapeo validado.

    Raises:
        AttckMappingLoadError: el archivo falta, está vacío, no es YAML
            válido o no cumple el schema (con el motivo exacto).
    """
    path = Path(path)
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as e:
        raise AttckMappingLoadError(f"no se pudo leer {path}: {e}") from e
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        raise AttckMappingLoadError(f"{path} no es YAML válido: {e}") from e
    if data is None:
        raise AttckMappingLoadError(f"{path} está vacío")
    try:
        return AttckMapping.model_validate(data)
    except ValidationError as e:
        raise AttckMappingLoadError(f"{path} no cumple el schema del mapeo ATT&CK: {e}") from e


@lru_cache(maxsize=1)
def get_mapping(path: Path | str = DEFAULT_MAPPING_PATH) -> tuple[AttckMapping, dict[str, AttckEntry]]:
    """Mapeo + índice de lookup, cargados UNA vez por proceso.

    Args:
        path: ruta del YAML; el parámetro existe para inyectar uno de prueba
            en los tests sin pisar el caché del real.

    Returns:
        (mapeo validado, índice nombre-corto/descripción -> entrada).

    Raises:
        AttckMappingLoadError: ver load_mapping(). lru_cache no cachea
            excepciones: por eso main.py lo llama en el lifespan.
    """
    mapping = load_mapping(path)
    return mapping, mapping.build_index()


def lookup(classtype: str | None, path: Path | str = DEFAULT_MAPPING_PATH) -> AttckEntry | None:
    """Entrada ATT&CK de un classtype (nombre corto o descripción).

    Args:
        classtype: valor tal como llega (header o alert.category); se
            normaliza con strip().lower().
        path: ver get_mapping().

    Returns:
        La entrada, o None si classtype es vacío/None o no está en el YAML.

    Raises:
        AttckMappingLoadError: el YAML no cargó (ver get_mapping()).
    """
    key = (classtype or "").strip().lower()
    if not key:
        return None
    _, index = get_mapping(path)
    return index.get(key)


def attack_fields(classtype: str | None, path: Path | str = DEFAULT_MAPPING_PATH) -> dict[str, str | None]:
    """Campos ATT&CK planos (ATTACK_FIELDS) para una decisión.

    Degradación con gracia: classtype vacío, sin entrada en el YAML, o YAML
    que no cargó -> todos los campos en None (el último caso se loguea en
    ERROR). Nunca lanza: corre en el Fast Path.

    Args:
        classtype: valor tal como llega a process_event().
        path: ver get_mapping().

    Returns:
        Diccionario con exactamente las claves de ATTACK_FIELDS. Una entrada
        que existe pero no tiene técnica (ej. "misc-attack") devuelve
        tactic/technique en None y confidence + versión poblados: se
        distingue "no aplica ATT&CK" de "classtype desconocido".
    """
    empty: dict[str, str | None] = dict.fromkeys(ATTACK_FIELDS)
    try:
        entry = lookup(classtype, path)
        if entry is None:
            return empty
        version = get_mapping(path)[0].version
    except AttckMappingLoadError as e:
        log.error(f"mapeo ATT&CK no disponible, decisión sin ATT&CK: {e}")
        return empty
    return {
        "attack_tactic_id": entry.tactic_id,
        "attack_tactic_name": entry.tactic_name,
        "attack_technique_id": entry.technique_id,
        "attack_technique_name": entry.technique_name,
        "attack_confidence": entry.confidence,
        "attack_mapping_version": version,
    }
