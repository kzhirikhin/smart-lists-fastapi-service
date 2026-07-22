from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Annotated, Optional


MAX_NOTE_LENGTH = 4_000
MAX_ITEM_NOTES = 10
MAX_ITEM_NOTES_CHARS = 8_000


def normalize_optional_text(value: object) -> object:
    """Нормализует переносы и превращает пустой пользовательский текст в None."""
    if isinstance(value, str):
        stripped = value.replace("\r\n", "\n").replace("\r", "\n").strip()
        return stripped or None
    return value


class ListItem(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    is_completed: bool
    note: Optional[str] = Field(default=None, max_length=MAX_NOTE_LENGTH)

    @field_validator("note", mode="before")
    @classmethod
    def strip_note(cls, value: object) -> object:
        return normalize_optional_text(value)


class NotesMeta(BaseModel):
    list_note_included: bool = False
    included_item_notes: int = Field(default=0, ge=0, le=MAX_ITEM_NOTES)
    omitted_item_notes: int = Field(default=0, ge=0)


class InsightRequest(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    items: list[ListItem] = Field(max_length=50)
    groups: list[Annotated[str, Field(min_length=1, max_length=100)]] = Field(default_factory=list, max_length=20)
    user_message: Optional[str] = Field(default=None, max_length=500)
    list_note: Optional[str] = Field(default=None, max_length=MAX_NOTE_LENGTH)
    notes_meta: NotesMeta = Field(default_factory=NotesMeta)

    @field_validator("user_message", "list_note", mode="before")
    @classmethod
    def strip_optional_text(cls, value: object) -> object:
        return normalize_optional_text(value)

    @model_validator(mode="after")
    def validate_item_notes_budget(self) -> "InsightRequest":
        """Не доверяем только web-клиенту: повторяем AI-бюджеты на границе сервиса."""
        item_notes = [item.note for item in self.items if item.note is not None]
        if len(item_notes) > MAX_ITEM_NOTES:
            raise ValueError(f"At most {MAX_ITEM_NOTES} item notes are allowed")
        if sum(len(note) for note in item_notes) > MAX_ITEM_NOTES_CHARS:
            raise ValueError(
                f"Item notes may contain at most {MAX_ITEM_NOTES_CHARS} characters in total"
            )
        return self


class InsightResponse(BaseModel):
    insight: str
