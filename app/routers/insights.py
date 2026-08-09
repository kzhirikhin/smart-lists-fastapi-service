import logging

from fastapi import APIRouter, Header, HTTPException, Request
from app.models.insights import InsightRequest, InsightResponse
from app.core.caller_auth import is_authorized
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
    # Google ID-токен либо shared secret — см. app/core/caller_auth.py.
    if not is_authorized(authorization):
        raise HTTPException(status_code=403, detail="Forbidden")

    completed_count = sum(1 for i in body.items if i.is_completed)
    sub_items_count = sum(len(i.sub_items) for i in body.items)
    # Заметки считаются по обоим уровням — так же, как их бюджет.
    item_notes_count = sum(1 for entry in body.iter_entries() if entry.note is not None)
    logger.info(
        "Insight requested: items=%d sub_items=%d completed=%d groups=%d "
        "has_user_msg=%s has_list_note=%s item_notes=%d omitted_item_notes=%d",
        len(body.items),
        sub_items_count,
        completed_count,
        len(body.groups),
        body.user_message is not None,
        body.list_note is not None,
        item_notes_count,
        body.notes_meta.omitted_item_notes,
    )

    insight_text = await ai.get_insight(
        title=body.title,
        items=body.items,
        groups=body.groups,
        user_message=body.user_message,
        list_note=body.list_note,
        notes_meta=body.notes_meta,
    )

    return InsightResponse(insight=insight_text)
