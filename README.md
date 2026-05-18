# Motor de decisión basado en riesgo para SOAR en SOC

Tesis UBO 2026 — Integración de Machine Learning calibrado con orquestación
de respuesta automatizada en un Security Operations Center.

## Componentes

- **`pipeline-ingesta/`** — Capa de ingesta y normalización: transforma logs
  crudos de Suricata al esquema del Golden Subset (11 features de NF-*-v3).
  Responsable: Antonio Ayala.
- **`ml-modelo/`** *(próximamente)* — Entrenamiento del modelo ML calibrado
  sobre el Golden Subset. Responsable: Joaquín Arias.
- **`motor-decision/`** *(próximamente)* — Motor de decisión basado en score
  calibrado, integrado con Wazuh active-response.

## Stack

Suricata → Vector → OpenSearch + Wazuh + FastAPI

## Equipo

- Antonio Ayala — infraestructura (ingesta, normalización, deploy)
- Joaquín Arias — modelo ML (entrenamiento, calibración)
- Miguel Castillo — profesor guía

## Plazos

- Julio 2026: sistema funcional en laboratorio (entrega semillero)
- Noviembre 2026: defensa de tesis (sistema operacional completo)
