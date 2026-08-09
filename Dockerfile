FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Непривилегированный пользователь. Cloud Run изолирует контейнер и сам по себе
# root внутри него мало что даёт, но внутри лежит ANTHROPIC_API_KEY, а сужение
# прав — единственный контроль, который здесь ничего не стоит. Раньше модель
# угроз засчитывала «non-root контейнер» в защиту, не имея на то оснований:
# директивы USER в образе не было вовсе.
#
# Права на /app не выдаём: приложение только читает свои файлы, а на запись ему
# нужен лишь HOME, который создаёт --create-home. Порт 8000 выше 1024, поэтому
# для bind привилегии не требуются.
RUN useradd --create-home --uid 10001 appuser
USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
