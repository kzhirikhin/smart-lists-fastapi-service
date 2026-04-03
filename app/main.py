from fastapi import FastAPI
from app.core.config import settings

app = FastAPI(title="Smart Lists AI Service")

@app.get("/health")
def health():
    return {"status": "ok"}