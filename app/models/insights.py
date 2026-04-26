from pydantic import BaseModel, Field
from typing import Annotated, Optional

ListItem = Annotated[str, Field(min_length=1, max_length=200)]

class InsightRequest(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    items: list[ListItem] = Field(max_length=50)
    user_message: Optional[str] = Field(default=None, max_length=500)

class InsightResponse(BaseModel):
    insight: str