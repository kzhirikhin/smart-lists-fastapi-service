from pydantic import BaseModel, Field, field_validator
from typing import Optional

class ListItem(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    is_completed: bool

class InsightRequest(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    items: list[ListItem] = Field(max_length=50)
    groups: list[str] = Field(default_factory=list, max_length=20)
    user_message: Optional[str] = Field(default=None, max_length=500)

    @field_validator("user_message", mode="before")
    @classmethod
    def strip_user_message(cls, v: object) -> object:
        if isinstance(v, str):
            stripped = v.strip()
            return stripped or None
        return v

class InsightResponse(BaseModel):
    insight: str