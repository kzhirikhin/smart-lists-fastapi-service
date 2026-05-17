import hmac
import logging

from fastapi import APIRouter, Header, HTTPException, Request
from app.models.insights import InsightRequest, InsightResponse
from app.core.config import settings
from app.core.limiter import limiter
from app.services import ai

logger = logging.getLogger(__name__)

router = APIRouter()

@router.post("/insights", response_model=InsightResponse)
@limiter.limit("5/minute")
async def get_insight(
    request: Request,
    body: InsightRequest,
    authorization: str = Header(...)
):
    expected = f"Bearer {settings.service_secret}"
    if not hmac.compare_digest(authorization, expected):
        raise HTTPException(status_code=403, detail="Forbidden")

    completed_count = sum(1 for i in body.items if i.is_completed)
    logger.info(
        "Insight requested: items=%d completed=%d groups=%d has_user_msg=%s",
        len(body.items), completed_count, len(body.groups), body.user_message is not None
    )

    insight_text = await ai.get_insight(
        title=body.title,
        items=body.items,
        groups=body.groups,
        user_message=body.user_message
    )

    return InsightResponse(insight=insight_text)
