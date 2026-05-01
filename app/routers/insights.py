import logging

from fastapi import APIRouter, Header, HTTPException
from app.models.insights import InsightRequest, InsightResponse
from app.core.config import settings
from app.services import ai

logger = logging.getLogger(__name__)

router = APIRouter()

@router.post("/insights", response_model=InsightResponse)
async def get_insight(
    request: InsightRequest,
    authorization: str = Header(...)
):
    expected = f"Bearer {settings.service_secret}"
    if authorization != expected:
        raise HTTPException(status_code=403, detail="Forbidden")

    logger.info("Insight requested: items=%d has_user_msg=%s", len(request.items), request.user_message is not None)

    insight_text = ai.get_insight(
        title=request.title,
        items=request.items,
        user_message=request.user_message
    )

    return InsightResponse(insight=insight_text)
