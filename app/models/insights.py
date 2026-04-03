from pydantic import BaseModel
from typing import Optional

class InsightRequest(BaseModel):
    title: str
    items: list[str]
    user_message: Optional[str] = None

class InsightResponse(BaseModel):
    insight: str