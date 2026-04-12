from fastapi import APIRouter, Header, HTTPException
from app.models.insights import InsightRequest, InsightResponse
from app.core.config import settings
from app.services import ai

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

    insight_text = ai.get_insight(
        title=request.title,
        items=request.items,
        user_message=request.user_message
    )

    return InsightResponse(insight=insight_text)