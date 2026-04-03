from fastapi import APIRouter, Header, HTTPException
from app.models.insights import InsightRequest, InsightResponse
from app.core.config import settings

router = APIRouter()

@router.post("/insights", response_model=InsightResponse)
async def get_insight(
    request: InsightRequest,
    authorization: str = Header(...)
):
    # Проверяем shared secret
    expected = f"Bearer {settings.service_secret}"
    if authorization != expected:
        raise HTTPException(status_code=403, detail="Forbidden")

    # Пока заглушка вместо реального AI
    return InsightResponse(
        insight=f"Анализирую список '{request.title}' с {len(request.items)} позициями..."
    )