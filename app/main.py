import logging
import time

from google.genai.errors import APIError
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.core.config import settings
from app.core.limiter import limiter
from app.core.logging_config import setup_logging
from app.core.request_boundary import InsightsBoundaryMiddleware
from app.routers.insights import router

setup_logging()
logger = logging.getLogger(__name__)

# Все три адреса гасятся одним флагом. Раньше `openapi_url` оставался дефолтным,
# и `DEBUG=false` убирал только интерфейсы: `/openapi.json` продолжал отдавать
# схему целиком — путь, обязательный заголовок, все поля и точные лимиты.
# Схема не секрет и доступа не даёт, но избавляет вызывающего от необходимости
# что-либо угадывать. Гасить UI, оставляя данные, из которых он строится, —
# ровно та половинчатость, которую документ называет «закрыто не там, где сломано».
app = FastAPI(
    title="Smart Lists AI Service",
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    openapi_url="/openapi.json" if settings.debug else None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.include_router(router)
app.add_middleware(InsightsBoundaryMiddleware)

@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.time()
    response = await call_next(request)

    if request.url.path == "/health":
        return response

    duration_ms = int((time.time() - start) * 1000)
    ip = request.headers.get("X-Forwarded-For", request.client.host).split(",")[0].strip()
    level = logging.WARNING if response.status_code >= 400 else logging.INFO
    logger.log(level, "ip=%s %s %s %d %dms", ip, request.method, request.url.path, response.status_code, duration_ms)

    return response


@app.exception_handler(APIError)
async def vertex_error_handler(request: Request, exc: APIError):
    # Тело и message vendor могут повторить часть prompt. В лог идут только
    # безопасные метаданные, а наружу — единая обезличенная ошибка.
    logger.error(
        "Vertex AI API error: status=%s type=%s",
        exc.code, type(exc).__name__,
    )
    return JSONResponse(
        status_code=502,
        content=dict(detail="AI provider request failed"),
    )


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    logger.error("AI service error: %s", exc)
    return JSONResponse(status_code=500, content={"detail": "AI service error"})


@app.get("/health")
def health():
    return {"status": "ok"}
