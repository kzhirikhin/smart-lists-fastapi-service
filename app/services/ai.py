import anthropic
from app.core.config import settings

client = anthropic.Anthropic(api_key=settings.anthropic_api_key)

def get_insight(title: str, items: list[str], user_message: str | None) -> str:
    system_prompt = """Ты помощник по анализу списков. Ты получаешь название списка
и его содержимое. Твоя задача — определить тип списка и дать
полезный, конкретный инсайт.

Правила:
- Отвечай кратко и по делу (2-4 предложения)
- Отвечай на том же языке что и содержимое списка
- Если передан вопрос пользователя — отвечай именно на него
- Если список пустой — вежливо сообщи что анализировать нечего"""

    user_prompt = f"""Список: {title}
Записи: {", ".join(items) if items else "пусто"}
Вопрос: {user_message if user_message else "не указан"}"""

    message = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=1024,
        system=system_prompt,
        messages=[
            {"role": "user", "content": user_prompt}
        ]
    )

    for block in message.content:
        if block.type == "text":
            return block.text
    raise ValueError("No text block in response")
