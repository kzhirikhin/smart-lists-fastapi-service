import logging
import time

import anthropic
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.core.config import settings
from app.core.limiter import limiter
from app.core.logging_config import setup_logging
from app.routers.insights import router

setup_logging()
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Smart Lists AI Service",
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.include_router(router)


@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > 100_000:
        return JSONResponse(status_code=413, content={"detail": "Request body too large"})
    return await call_next(request)


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


@app.exception_handler(anthropic.APIStatusError)
async def anthropic_error_handler(request: Request, exc: anthropic.APIStatusError):
    logger.error("Anthropic API error: status=%d %s", exc.status_code, exc.message)
    return JSONResponse(status_code=502, content={"detail": "AI service unavailable"})


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    logger.error("AI service error: %s", exc)
    return JSONResponse(status_code=500, content={"detail": "AI service error"})


@app.get("/health")
def health():
    return {"status": "ok"}
