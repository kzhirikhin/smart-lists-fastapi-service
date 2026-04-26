from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from app.core.config import settings
from app.routers.insights import router

app = FastAPI(title="Smart Lists AI Service")

app.include_router(router)


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    return JSONResponse(status_code=500, content={"detail": "AI service error"})


@app.get("/health")
def health():
    return {"status": "ok"}