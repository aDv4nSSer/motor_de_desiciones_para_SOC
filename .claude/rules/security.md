# Estándares de Seguridad

Aplica a todos los servicios sin excepción. Este sistema monitorea infraestructura de seguridad:
un fallo de seguridad en el motor compromete directamente lo que el motor protege.

## Gestión de secrets y configuración

```python
# CORRECTO: Pydantic Settings — todos los secrets desde entorno
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    redis_url: str
    opensearch_url: str
    opensearch_user: str
    opensearch_password: str
    abuseipdb_api_key: str
    otx_api_key: str
    internal_api_key: str       # autenticación inter-servicio
    shap_threshold: float = 0.7 # calcular SHAP solo sobre este umbral

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

settings = Settings()  # singleton — instanciar una vez al inicio
```

- `.env` siempre en `.gitignore`. Proveer `.env.example` con valores ficticios, nunca reales.
- `detect-secrets` en pre-commit bloquea cualquier secret en código antes del commit.
- Secrets en Docker Compose via `environment:` desde `.env`, nunca hardcodeados en `compose.yml`.

## Autenticación inter-servicio

Los tres servicios del Enrichment Path requieren `X-Internal-Key` en cada request.

```python
import secrets
from fastapi import Header, HTTPException

async def verify_internal_key(
    x_internal_key: str = Header(..., alias="X-Internal-Key")
) -> None:
    if not secrets.compare_digest(
        x_internal_key.encode(), settings.internal_api_key.encode()
    ):
        raise HTTPException(status_code=401, detail="Unauthorized")
    # secrets.compare_digest es timing-safe — nunca usar == para comparar tokens
```

Usar como dependencia en todos los endpoints internos del pipeline.

## Validación de inputs — toda entrada externa es untrusted

```python
from pydantic import BaseModel, Field, field_validator
import ipaddress

class EnrichRequest(BaseModel):
    indicator: str = Field(..., min_length=1, max_length=255, pattern=r'^[\w.\-:/\[\]]+$')
    type: Literal["ip", "domain", "hash"]

    @field_validator("indicator")
    @classmethod
    def validate_and_sanitize(cls, v: str, info) -> str:
        v = v.strip()
        if info.data.get("type") == "ip":
            try:
                ipaddress.ip_address(v)  # valida IPv4 e IPv6
            except ValueError:
                raise ValueError(f"IP inválida: {v}")
        return v.lower()
```

- Validar tipo, longitud y formato en TODO input externo antes de usarlo en queries u operaciones.
- Nunca interpolar inputs sin validar en queries DSL de OpenSearch — usar el DSL object, no f-strings.
- Sanitizar toda respuesta de API externa antes de persistirla — no confiar en el schema del proveedor.
- Rechazar requests con `Content-Type` incorrecto antes de procesar el body.

## Logging seguro — qué NO registrar

```python
import structlog
logger = structlog.get_logger()

# CORRECTO
logger.info("ti_lookup", trace_id=trace_id, indicator_type="ip",
            provider="abuseipdb", cache_hit=True, verdict="malicious")

# INCORRECTO — nunca así
logger.debug(f"Calling {url}?key={api_key}&ip={full_ip}")  # secret + PII
logger.info(request.body())                                  # payload completo
```

- Sin API keys ni tokens en logs bajo ningún nivel (incluyendo DEBUG).
- Sin IPs completas en logs INFO/DEBUG en producción cuando identifiquen usuarios concretos.
- Sin payloads completos de requests externos en producción.
- `ERROR` o superior para fallos de servicios externos. `WARNING` para degradaciones esperadas.
- Estructurar siempre con campos clave-valor, nunca con strings interpolados.

## Dependencias externas (APIs de Threat Intelligence)

- Timeout máximo: `connect=2.0s, read=5.0s` — nunca esperar indefinidamente.
- Rate limiting: token bucket en Redis `ti:rate:{provider}:{minute}` antes de cada llamada.
- Circuit breaker por proveedor:
  - Abierto tras N fallos consecutivos → omitir proveedor por M minutos.
  - Estado `unavailable` en `NormalizedTI.sources` cuando el circuito está abierto.
  - La decisión NUNCA se bloquea por un proveedor con circuito abierto.
- Validar schema de respuesta del proveedor antes de normalizar — puede cambiar sin previo aviso.

## Análisis estático (bandit)

Pre-commit ejecuta `bandit -r . -ll` antes de cada commit:
- Findings `HIGH`: bloquean el commit sin excepción.
- Findings `MEDIUM`: requieren revisión y supresión explícita con `# nosec BXXX` + comentario
  que justifique por qué es un falso positivo en este contexto concreto.
- Ejecutar `bandit -r . -f json -o bandit-report.json` para reporte completo en CI.
