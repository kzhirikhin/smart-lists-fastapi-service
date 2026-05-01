import logging
import time

import anthropic
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.logging_config import setup_logging
from app.routers.insights import router

setup_logging()
logger = logging.getLogger(__name__)

app = FastAPI(title="Smart Lists AI Service")

app.include_router(router)


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
