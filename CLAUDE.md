# Motor de Decisiones para SOC — Guía del Proyecto

## Reglas absolutas de seguridad

- **Nunca** hardcodear secretos, contraseñas, IPs ni credenciales en el código fuente.
- Todos los secretos residen en `.env` (archivo ignorado por git).
- En Python, acceder a config exclusivamente con `os.getenv("VARIABLE")` o `pydantic-settings`.
- `.env.example` es el contrato público de qué variables se necesitan — sin valores reales.
- Si un commit introduce un secreto, debe revertirse antes de pushearse.

## Estilo de código Python

- **Type hints obligatorios** en toda función y método:
  ```python
  def score_alert(event: dict[str, Any], threshold: float) -> AlertScore:
  ```
- **Logging estructurado** con `structlog` o `logging` + `json` formatter — nunca `print()` en producción.
- Formato: `black` + `isort`. Linting: `ruff`.
- Docstrings solo cuando el WHY no es obvio desde el código.

## Flujo de ramas git

| Rama | Propósito |
|------|-----------|
| `main` | Producción — solo merges desde `develop` vía PR aprobado |
| `develop` | QA / staging — integración continua |
| `feature/*` | Desarrollo de funcionalidad nueva |
| `fix/*` | Correcciones puntuales |
| `chore/*` | Tareas técnicas sin impacto funcional |

Regla: **nunca pushear directo a `main`**. Todo cambio entra por PR con al menos una revisión.

## Estructura del proyecto

```
motor_de_desiciones_para_SOC/
├── api/               # FastAPI — endpoints, schemas, middleware
├── motor/             # Lógica de decisiones: reglas, scoring, respuesta
├── pipeline-ingesta/  # Vector + Suricata — ingesta de eventos
├── tests/             # unit/ e integration/
└── .env.example       # Variables requeridas (sin valores reales)
```

## Variables de entorno

Ver `.env.example` para la lista completa. Acceso en Python:

```python
import os

OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "localhost")
```

Usar `pydantic-settings` para validación en el arranque de la app:

```python
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    opensearch_host: str
    opensearch_port: int = 9200

    class Config:
        env_file = ".env"
```

## Pre-commit hooks

Antes de hacer commit, los hooks verifican:
- `detect-secrets`: bloquea si detecta un secreto en el diff.
- `bandit`: análisis estático de seguridad Python (nivel MEDIUM+).
- `check-merge-conflict`: bloquea markers `<<<<<<<`.
- `trailing-whitespace`, `end-of-file-fixer`.

Instalar una vez con: `pre-commit install`

## Tests

- Tests unitarios en `tests/unit/` — sin I/O real, sin red.
- Tests de integración en `tests/integration/` — pueden usar servicios locales con docker-compose.
- Correr con: `pytest tests/unit` (rápido) o `pytest` (completo).
