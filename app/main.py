from fastapi import FastAPI
from app.core.config import settings
from app.routers.insights import router

app = FastAPI(title="Smart Lists AI Service")

app.include_router(router)


@app.get("/health")
def health():
    return {"status": "ok"}