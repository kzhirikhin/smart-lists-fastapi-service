import hmac
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
    if not hmac.compare_digest(authorization, expected):
        raise HTTPException(status_code=403, detail="Forbidden")

    completed_count = sum(1 for i in request.items if i.is_completed)
    logger.info(
        "Insight requested: items=%d completed=%d groups=%d has_user_msg=%s",
        len(request.items), completed_count, len(request.groups), request.user_message is not None
    )

    insight_text = ai.get_insight(
        title=request.title,
        items=request.items,
        groups=request.groups,
        user_message=request.user_message
    )

    return InsightResponse(insight=insight_text)
