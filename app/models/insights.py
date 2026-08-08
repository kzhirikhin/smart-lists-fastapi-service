from collections.abc import Iterator
from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Annotated, Optional


MAX_NOTE_LENGTH = 4_000
MAX_ITEM_NOTES = 10
MAX_ITEM_NOTES_CHARS = 8_000
MAX_SUB_ITEMS = 100


def normalize_optional_text(value: object) -> object:
    """Нормализует переносы и превращает пустой пользовательский текст в None."""
    if isinstance(value, str):
        stripped = value.replace("\r\n", "\n").replace("\r", "\n").strip()
        return stripped or None
    return value


class SubItem(BaseModel):
    """Подпункт: часть своего пункта, собственных подпунктов иметь не может.

    Отдельная модель, а не рекурсивная ссылка на `ListItem`: вложенность в
    контракте ровно одна, и выразить это типом надёжнее, чем проверкой глубины.
    """

    name: str = Field(min_length=1, max_length=200)
    is_completed: bool
    note: Optional[str] = Field(default=None, max_length=MAX_NOTE_LENGTH)

    @field_validator("note", mode="before")
    @classmethod
    def strip_note(cls, value: object) -> object:
        return normalize_optional_text(value)


class ListItem(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    is_completed: bool
    note: Optional[str] = Field(default=None, max_length=MAX_NOTE_LENGTH)
    # default_factory, а не обязательное поле: вызывающая сторона могла быть
    # выпущена до подпунктов, и запрос без этого ключа обязан работать.
    sub_items: list[SubItem] = Field(default_factory=list, max_length=MAX_SUB_ITEMS)

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

    def iter_entries(self) -> Iterator[ListItem | SubItem]:
        """Записи обоих уровней: пункт, следом его подпункты.

        Бюджеты и счётчики заметок считаются по этому обходу: для модели
        заметка подпункта ничем не отличается от заметки пункта, и раздельный
        счёт открыл бы обход лимита через вложенность.
        """
        for item in self.items:
            yield item
            yield from item.sub_items

    @model_validator(mode="after")
    def validate_sub_items_budget(self) -> "InsightRequest":
        """Совокупный лимит подпунктов: поштучный на пункт его не заменяет."""
        sub_item_count = sum(len(item.sub_items) for item in self.items)
        if sub_item_count > MAX_SUB_ITEMS:
            raise ValueError(f"At most {MAX_SUB_ITEMS} sub-items are allowed in total")
        return self

    @model_validator(mode="after")
    def validate_item_notes_budget(self) -> "InsightRequest":
        """Не доверяем только web-клиенту: повторяем AI-бюджеты на границе сервиса."""
        item_notes = [
            entry.note for entry in self.iter_entries() if entry.note is not None
        ]
        if len(item_notes) > MAX_ITEM_NOTES:
            raise ValueError(f"At most {MAX_ITEM_NOTES} item notes are allowed")
        if sum(len(note) for note in item_notes) > MAX_ITEM_NOTES_CHARS:
            raise ValueError(
                f"Item notes may contain at most {MAX_ITEM_NOTES_CHARS} characters in total"
            )
        return self


class InsightResponse(BaseModel):
    insight: str
