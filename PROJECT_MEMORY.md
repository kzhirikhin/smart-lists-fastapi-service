# Память проекта Smart Lists AI Service

> Живой снимок устойчивых знаний о проекте. Перед работой сверяй его с кодом и
> обновляй после существенных изменений.

**Последнее обновление:** 2026-07-29  
**Состояние:** активная разработка

## Назначение

Smart Lists AI Service — отдельный FastAPI-сервис для AI-инсайтов
web-приложения Smart Lists. Он получает ограниченный снимок списка, формирует
защищённый prompt, вызывает Anthropic Claude и возвращает текст ответа.

Сервис не хранит данные и не знает пользователей. Граница ответственности
разделена так:

- Smart Lists web-приложение аутентифицирует пользователя, проверяет доступ к
  списку, читает данные из PostgreSQL и применяет суточную квоту;
- этот сервис аутентифицирует вызывающий backend shared secret, повторно
  валидирует payload, ограничивает нагрузку, изолирует недоверенный текст в
  prompt и общается с Anthropic;
- Cloud Run и Google Cloud задают ingress, TLS, IAM и runtime secrets.

## Актуальный стек

- Python 3.13;
- FastAPI `0.135.3`, Starlette `1.3.1`, Uvicorn `0.42.0`;
- Pydantic `2.12.5` и pydantic-settings `2.14.2`;
- Anthropic SDK `0.88.0`;
- SlowAPI `0.1.9`;
- pytest `9.0.3`, pytest-asyncio и FastAPI TestClient;
- Docker, Google Artifact Registry и Google Cloud Run;
- GitHub Actions, GitHub OIDC и Google Workload Identity Federation.

Точные версии всегда смотри в `requirements.txt`. Python version должна
совпадать в `Dockerfile`, `ci.yml` и `deploy.yml`.

## Карта репозитория

- `app/main.py` — FastAPI app, middleware размера тела и access log,
  exception handlers, `/health`;
- `app/core/config.py` — env-backed настройки;
- `app/core/limiter.py` — SlowAPI limiter и извлечение source IP;
- `app/core/logging_config.py` — базовая конфигурация stdout logging;
- `app/models/insights.py` — request/response contract, нормализация и бюджеты;
- `app/routers/insights.py` — Bearer authentication, rate limit и orchestration;
- `app/services/ai.py` — prompt, сериализация недоверенных данных и Anthropic;
- `tests/` — API-, validation- и prompt-boundary тесты;
- `bruno/Smart Lists API/` — ручные запросы health и insight;
- `.github/workflows/ci.yml` — тесты и full-history Gitleaks;
- `.github/workflows/deploy.yml` — test-gated keyless deployment;
- `Dockerfile` — production image;
- `docker-compose.yml` — альтернативный запуск старого GHCR `latest` image,
  не описание Cloud Run deployment.

## HTTP-контракт

### `GET /health`

- публичный liveness endpoint;
- возвращает `{"status": "ok"}`;
- не проверяет Anthropic и другие внешние зависимости;
- исключён из обычного request log.

### `POST /insights`

- защищён обязательным `Authorization` header;
- ожидаемое значение — `Bearer <SERVICE_SECRET>`;
- сравнение выполняется через `hmac.compare_digest`;
- endpoint ограничен декоратором SlowAPI `5/minute`;
- успешный ответ имеет форму `{"insight": "<text>"}`.

Основной request:

- `title: str`;
- `items: list[{name, is_completed, note?}]`;
- `groups: list[str]`, по умолчанию пустой;
- `user_message: str | null`;
- `list_note: str | null`;
- `notes_meta: {list_note_included, included_item_notes,
  omitted_item_notes}`, по умолчанию нулевой.

`list_note_included` и `included_item_notes` в prompt вычисляются заново из
валидированного payload. Из переданного `notes_meta` доверяется только
`omitted_item_notes`: его нельзя восстановить, потому что соответствующие
заметки намеренно не присланы web-приложением.

## Лимиты и нормализация

| Поле или ресурс | Лимит |
| --- | --- |
| `Content-Length` | не более 100 000 байт |
| `title` | 1–200 символов |
| `items` | не более 50 |
| `items[*].name` | 1–200 символов |
| `groups` | не более 20 |
| `groups[*]` | 1–100 символов |
| `user_message` | не более 500 символов |
| `list_note` | не более 4 000 символов |
| `items[*].note` | не более 4 000 символов |
| непустые item notes | не более 10 |
| сумма item notes | не более 8 000 символов |
| запросы `/insights` | 5 в минуту на source IP и процесс |
| Anthropic timeout | 30 секунд |
| Anthropic output | `max_tokens=2048` |

Для `user_message`, `list_note` и item note:

- CRLF и одиночный CR нормализуются в LF;
- крайние пробелы удаляются;
- пустая после нормализации строка превращается в `None`.

Ограничение `Content-Length` — ранняя защита, а не полноценный streaming body
limit: при отсутствии заголовка middleware не измеряет фактически прочитанные
байты. Содержательные Pydantic-бюджеты действуют независимо.

## Ключевой поток запроса

1. Web Server Action `getListInsight` проверяет сессию и доступ к списку через
   БД, выбирает ограниченный набор записей и заметок и атомарно применяет лимит
   15 запросов на пользователя в UTC-день.
2. Web backend вызывает `${INSIGHTS_SERVICE_URL}/insights`, передавая
   `Authorization: Bearer ${INSIGHTS_SERVICE_SECRET}`.
3. FastAPI отклоняет слишком большой объявленный body, а router применяет
   per-IP rate limit и constant-time проверку secret.
4. Pydantic нормализует и валидирует поля и совокупный note budget.
5. `get_insight` определяет требуемую глубину ответа по числу записей,
   пересчитывает проверяемые note counters и строит payload.
6. Payload сериализуется в JSON с `ensure_ascii=False`, затем `&`, `<` и `>`
   заменяются на unicode escape sequences.
7. JSON помещается в единственный блок `<untrusted_user_data_json>`.
8. Асинхронный Anthropic client вызывает модель
   `claude-haiku-4-5-20251001`.
9. Первый текстовый content block возвращается клиенту. Отсутствие такого блока
   считается ошибкой.

## Модель безопасности

### Аутентификация и авторизация

- Shared Bearer secret аутентифицирует сервис Smart Lists, а не конечного
  пользователя.
- Пользовательская сессия, принадлежность списка пространству и права
  владельца/редактора проверяются в web-репозитории до вызова API.
- Секрет существует только на серверной стороне обоих приложений.
- `/health` публичен по назначению; `/insights` без корректного header не
  вызывает Anthropic.

### Prompt injection

- Все поля payload считаются недоверенным пользовательским содержимым.
- Данные не интерполируются в system prompt.
- XML-подобный boundary нельзя закрыть через `<`, `>` или `&` из JSON.
- System prompt явно запрещает выполнять команды из payload, менять правила и
  раскрывать системные инструкции.
- Ответ модели остаётся недоверенным выводом; безопасный рендеринг принадлежит
  потребителю.

### Стоимость и отказоустойчивость

- Web-приложение держит авторитетную суточную квоту на пользователя.
- Этот сервис добавляет локальный защитный rate limit по IP.
- Все размеры контекста и выход модели ограничены.
- Anthropic client имеет конечный timeout.
- Автоматические повторы отсутствуют, поэтому сервис сам не умножает стоимость
  одного входящего запроса.

### Логирование и ошибки

- Access log: source IP, method, path, status и duration.
- Insight log: количество записей, выполненных записей, групп и заметок,
  булевы признаки наличия вопроса и заметки списка.
- Не логируются Bearer header, API key, title, item names, note text,
  `user_message`, полный prompt и успешный AI response.
- `anthropic.APIStatusError` преобразуется в generic `502`.
- `ValueError`, включая отсутствие text block, преобразуется в generic `500`.
- Остальные исключения обрабатываются стандартным механизмом FastAPI.

### Границы текущих защит

- SlowAPI использует память процесса; при нескольких Cloud Run instances лимит
  не общий.
- `_get_real_ip` доверяет первому `X-Forwarded-For`. Это корректно только за
  контролируемым ingress. При прямом доступе клиент мог бы влиять на ключ
  limiter.
- Репозиторий не описывает Cloud Run ingress policy и способ подключения
  runtime secrets; это внешняя инфраструктура.
- `DEBUG=true` публикует OpenAPI UI и допустим только локально.

## Конфигурация

`Settings` читает `.env` локально и environment variables во всех средах:

| Переменная | Обязательность | Назначение |
| --- | --- | --- |
| `SERVICE_SECRET` | обязательна | shared Bearer secret |
| `ANTHROPIC_API_KEY` | обязательна | ключ Anthropic |
| `DEBUG` | необязательна | включает `/docs` и `/redoc`, default `false` |

Settings и глобальный Anthropic client создаются при импорте модулей. Поэтому
даже тестам нужны placeholder env values до импорта `app.main`; в CI они
заведомо нерабочие, а вызов Anthropic замокан.

Корневой `.env` игнорируется Git и предназначен только для development.
Production-значения не должны попадать в репозиторий, GitHub test jobs, Bruno
collection или Docker image.

## Связь с web-репозиторием

Источник вызывающего контракта —
`smart-lists/src/app/actions/insights.ts`.

Web-приложение:

- берёт данные списка из PostgreSQL, а не из браузерного payload;
- проверяет пользователя и доступ в контексте `spaceId`;
- выбирает максимум 50 записей;
- отдельно выбирает до 10 записей с заметками в пределах 8 000 символов;
- передаёт число намеренно опущенных заметок;
- обрезает title, item names, notes и question до совместимых лимитов;
- применяет 15 AI-запросов на пользователя в UTC-день;
- передаёт `INSIGHTS_SERVICE_URL` и `INSIGHTS_SERVICE_SECRET` только на сервере.

При изменении request model, имён полей или лимитов оба репозитория меняются
синхронно.

## Локальная разработка

Минимальный PowerShell-поток:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
uvicorn app.main:app --reload
```

Нужен `.env` с development-значениями `ANTHROPIC_API_KEY`,
`SERVICE_SECRET` и, при необходимости, `DEBUG=true`.

Bruno collection содержит ручные запросы. Её `secret` — secret variable и не
должен сохраняться в коллекции. Текущий `base_url` указывает на Cloud Run,
поэтому перед ручным запросом всегда явно проверь выбранное окружение.

## Тесты

Команда полного прогона:

```bash
pytest tests/ -v
```

Сейчас в `tests/test_insights.py` 18 test functions, включая
параметризованный тест бюджетов. Покрыты:

- health;
- успешный insight с Anthropic mock;
- неверный и отсутствующий Authorization;
- границы title, items, item names, question и notes;
- нормализация whitespace-only optional text;
- список без записей и список только с общей заметкой;
- сохранение связи item note с записью и status;
- передача `omitted_item_notes`;
- невозможность закрыть untrusted-data block через пользовательский текст.

Autouse fixture сбрасывает in-memory limiter между тестами. Production
декоратор при этом остаётся активным. Сеть и настоящий Anthropic API в тестах
не используются.

## CI

`.github/workflows/ci.yml` запускается для веток и PR, но устраняет дубли:

- push в `main` проверяется test job из deploy workflow;
- PR из ветки того же репозитория уже покрыт push;
- tests job получает только `test-key` и `test-secret-123`;
- secrets job запускает Gitleaks по полной истории с `--redact`;
- workflow token имеет только `contents: read`;
- CI ничего не деплоит.

На приватном репозитории встроенный GitHub secret scanning может быть
недоступен, поэтому Gitleaks — обязательная отдельная защита.

## Deployment

`.github/workflows/deploy.yml` запускается на push в `main`.

- `test` устанавливает зависимости и запускает pytest с fake credentials;
- `deploy` зависит от успешного `test`;
- только `deploy` получает `id-token: write`;
- GitHub OIDC обменивается через Workload Identity Federation на временные
  права service account
  `github-deployer@project-5b7c1bd1-572b-410d-826.iam.gserviceaccount.com`;
- image публикуется в
  `us-central1-docker.pkg.dev/project-5b7c1bd1-572b-410d-826/smart-lists/insights-api`;
- создаются теги commit SHA и `latest`;
- Cloud Run service `insights-api` в `us-central1` разворачивается по SHA tag.

Long-lived GCP JSON key в GitHub нет. Runtime `SERVICE_SECRET` и
`ANTHROPIC_API_KEY` должны быть настроены вне репозитория в Cloud Run.

`docker-compose.yml` всё ещё ссылается на
`ghcr.io/kiriu237011/smart-lists-fastapi-service:latest`. Это альтернативный
или legacy способ запуска; активный production pipeline использует Artifact
Registry и не обновляет GHCR image.

## Важные решения

- 2026-07-29: CI отделён от deployment, получает только fake credentials и
  минимальный `contents: read`. История сканируется Gitleaks, а deploy использует
  keyless OIDC/WIF вместо service-account key.
- 2026-07-29: Python в CI приведён к 3.13, то есть к production image. Версии
  FastAPI/Starlette/httpx закреплены совместимым набором, чтобы TestClient
  работал одинаково локально и на runner.
- 2026-07-22: в AI-контракт добавлены list note, item notes и `notes_meta`.
  Отдельные количество и суммарный бюджет заметок повторно проверяются на
  границе FastAPI, а проверяемые counters пересчитываются из payload.
- 2026-07-22: пользовательские данные отделены от инструкций единственным
  `<untrusted_user_data_json>` блоком. Символы закрытия boundary экранируются,
  а регрессия покрыта тестом prompt injection.
- 2026-07-19: production deployment перенесён в Google Cloud Run. GitHub
  собирает SHA-tagged image в Artifact Registry и разворачивает immutable tag.
- Rate limit этого сервиса оставлен дополнительным in-memory per-IP барьером,
  потому что авторитетная пользовательская квота хранится в PostgreSQL
  web-приложения. Он не должен подменять распределённый cost control.
- Health check намеренно не зависит от Anthropic: liveness должен показывать,
  что процесс отвечает, а временный отказ vendor не должен вызывать
  бесконечную замену исправных instances.

## Как поддерживать этот файл

- Обновляй дату и только затронутые разделы после архитектурных, продуктовых,
  security или deployment изменений.
- Добавляй решение, если оно объясняет компромисс, который следующий агент
  иначе может случайно отменить.
- Удаляй сведения, которые перестали быть правдой.
- Не превращай файл в журнал коммитов, список выполненных шагов, дамп логов или
  хранилище секретов и пользовательских данных.
