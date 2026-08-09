# Память проекта Smart Lists AI Service

> Живой снимок устойчивых знаний о проекте. Перед работой сверяй его с кодом и
> обновляй после существенных изменений.

**Последнее обновление:** 2026-08-09 (shared secret удалён)

**Состояние:** активная разработка

## Назначение

Smart Lists AI Service — отдельный FastAPI-сервис для AI-инсайтов
web-приложения Smart Lists. Он получает ограниченный снимок списка, формирует
защищённый prompt, вызывает Anthropic Claude и возвращает текст ответа.

Сервис не хранит данные и не знает пользователей. Граница ответственности
разделена так:

- Smart Lists web-приложение аутентифицирует пользователя, проверяет доступ к
  списку, читает данные из PostgreSQL и применяет суточную квоту;
- этот сервис аутентифицирует вызывающий backend по Google ID-токену, повторно
  валидирует payload, ограничивает нагрузку, изолирует недоверенный текст в
  prompt и общается с Anthropic;
- Cloud Run и Google Cloud задают ingress, TLS, IAM и runtime secrets.

## Актуальный стек

- Python 3.13;
- FastAPI `0.135.3`, Starlette `1.3.1`, Uvicorn `0.42.0`;
- Pydantic `2.12.5` и pydantic-settings `2.14.2`;
- Anthropic SDK `0.88.0`;
- SlowAPI `0.1.9`;
- google-auth `2.56.3` и requests `2.34.2` — проверка Google ID-токенов;
- pytest `9.0.3`, pytest-asyncio и FastAPI TestClient;
- Docker, Google Artifact Registry и Google Cloud Run;
- GitHub Actions, GitHub OIDC и Google Workload Identity Federation.

Точные версии всегда смотри в `requirements.txt`. Python version должна
совпадать в `Dockerfile`, `ci.yml` и `deploy.yml`.

## Карта репозитория

- `app/main.py` — FastAPI app, middleware размера тела и access log,
  exception handlers, `/health`;
- `app/core/config.py` — env-backed настройки;
- `app/core/caller_auth.py` — проверка вызывающего по Google ID-токену;
- `app/core/limiter.py` — SlowAPI limiter и извлечение source IP;
- `app/core/logging_config.py` — базовая конфигурация stdout logging;
- `app/models/insights.py` — request/response contract, нормализация и бюджеты;
- `app/routers/insights.py` — rate limit, проверка вызывающего и orchestration;
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
- ожидаемое значение — `Bearer <Google ID-токен>`;
- токен проверяется `google-auth` по подписи, `aud` и `email` вызывающего;
- endpoint ограничен декоратором SlowAPI `5/minute`;
- успешный ответ имеет форму `{"insight": "<text>"}`.

Основной request:

- `title: str`;
- `items: list[{name, is_completed, note?, sub_items?}]`;
- `items[*].sub_items: list[{name, is_completed, note?}]`, по умолчанию пустой;
- `groups: list[str]`, по умолчанию пустой;
- `user_message: str | null`;
- `list_note: str | null`;
- `notes_meta: {list_note_included, included_item_notes,
  omitted_item_notes}`, по умолчанию нулевой.

`list_note_included` и `included_item_notes` в prompt вычисляются заново из
валидированного payload. Из переданного `notes_meta` доверяется только
`omitted_item_notes`: его нельзя восстановить, потому что соответствующие
заметки намеренно не присланы web-приложением.

Вложенность ровно одна: `SubItem` — отдельная модель без собственного
`sub_items`, поэтому второй уровень не выражается контрактом и не требует
проверки глубины. `sub_items` необязателен и по умолчанию пуст — вызывающая
сторона, выпущенная до подпунктов, продолжает работать без изменений. Заметки
подпунктов входят в тот же бюджет, что и заметки пунктов: раздельный счёт
открыл бы обход лимита через вложенность.

## Лимиты и нормализация

| Поле или ресурс | Лимит |
| --- | --- |
| `Content-Length` | не более 100 000 байт |
| `title` | 1–200 символов |
| `items` | не более 50 |
| `items[*].name` | 1–200 символов |
| `items[*].sub_items` | не более 100 у одного пункта и 100 суммарно |
| `items[*].sub_items[*].name` | 1–200 символов |
| `items[*].sub_items[*].note` | не более 4 000 символов |
| `groups` | не более 20 |
| `groups[*]` | 1–100 символов |
| `user_message` | не более 500 символов |
| `list_note` | не более 4 000 символов |
| `items[*].note` | не более 4 000 символов |
| непустые item notes обоих уровней | не более 10 |
| сумма item notes обоих уровней | не более 8 000 символов |
| запросы `/insights` | 5 в минуту на source IP и процесс |
| Anthropic timeout | 30 секунд на попытку |
| Anthropic retries | 2 повтора — дефолт SDK, явно не задан |
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
2. Web backend вызывает `${INSIGHTS_SERVICE_URL}/insights`. В `Authorization`
   едет Google ID-токен, выпущенный через Workload Identity Federation.
3. Cloud Run проверяет право звать по IAM ещё до контейнера. Затем FastAPI
   отклоняет слишком большой объявленный body, а router применяет per-IP rate
   limit и проверку вызывающего.
4. Pydantic нормализует и валидирует поля и совокупный note budget.
5. `get_insight` определяет требуемую глубину ответа по числу записей обоих
   уровней, пересчитывает проверяемые note counters и строит payload:
   подпункты уходят вложенным `sub_items` внутри своего пункта, пустой список
   в payload не выводится.
6. Payload сериализуется в JSON с `ensure_ascii=False`, затем `&`, `<` и `>`
   заменяются на unicode escape sequences.
7. JSON помещается в единственный блок `<untrusted_user_data_json>`.
8. Асинхронный Anthropic client вызывает модель
   `claude-haiku-4-5-20251001`.
9. Первый текстовый content block возвращается клиенту. Отсутствие такого блока
   считается ошибкой.

## Модель безопасности

### Аутентификация и авторизация

Проверяется вызывающий сервис, а не конечный пользователь. Пользовательская
сессия, принадлежность списка пространству и права владельца/редактора
проверяются в web-репозитории до вызова API.

Способ один: **Google ID-токен в `Authorization`** (`app/core/caller_auth.py`).
Cloud Run проверяет его сам до того, как запрос дойдёт до кода, а сервис
проверяет повторно и независимо: подпись публичными ключами Google, `aud` и
`email` вызывающего против `EXPECTED_CALLER_SA`. Вторая проверка не дублирует
первую: если IAM снова окажется распахнутым, платформа не проверит ничего, и
подпись останется единственным барьером — а подделать её нельзя.

Shared Bearer secret удалён 2026-08-09. Ротировать больше нечего: статического
секрета нет ни здесь, ни в вызывающем приложении.

Токен доходит до контейнера целым только из заголовка `Authorization`. У
`X-Serverless-Authorization` Cloud Run вырезает подпись, заменяя её на
`SIGNATURE_REMOVED_BY_GOOGLE`: claims читаются, подлинность — нет. Проверено
экспериментом 2026-08-09, документация об этом прямо не пишет.

`SERVICE_AUDIENCE` принимает список через запятую: у сервиса Cloud Run два
действующих адреса, и токен выпускается под тот, что настроен у вызывающего.

- Токен существует только на серверной стороне и живёт около часа.
- `/health` публичен по назначению; `/insights` без корректного header не
  вызывает Anthropic.
- Проверка подписи требует публичных ключей Google: библиотека забирает их по
  сети и кеширует, поэтому первая проверка после холодного старта ходит наружу.
  Недоступность этого эндпоинта означает отказ в обслуживании, а не пропуск
  непроверенных запросов.

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
- Anthropic client имеет конечный timeout — 30 секунд на попытку.
- `max_retries` клиенту явно не передан, поэтому действует дефолт SDK: два
  автоматических повтора, то есть до трёх попыток на один входящий запрос.
  По деньгам это почти незаметно — повторяются неуспешные вызовы, которые
  обычно не тарифицируются. Значимо другое: худший случай удерживает воркер
  около 90 секунд вместо 30, и порог насыщения инстансов оказывается втрое
  ниже наивной оценки по timeout. Если повторы понадобится убрать, задавай
  `max_retries=0` явно — молчание здесь означает «два», а не «ноль».

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
- `Dockerfile` не содержит `USER`, поэтому uvicorn стартует под root, а
  `deploy.yml` этого не переопределяет. Внутри контейнера ценен только
  `ANTHROPIC_API_KEY`, доступный процессу при любом UID, поэтому эффект
  ограничен — но описывать контейнер как non-root нельзя.
- Поле `groups` остаётся в контракте, хотя web-приложение его не отправляет.
  Для вызывающего мимо приложения это до 20 строк по 100 символов свободного
  текста, попадающего в prompt.

## Конфигурация

`Settings` читает `.env` локально и environment variables во всех средах:

| Переменная | Обязательность | Назначение |
| --- | --- | --- |
| `ANTHROPIC_API_KEY` | обязательна | ключ Anthropic |
| `DEBUG` | необязательна | включает `/docs`, `/redoc` и `/openapi.json`, default `false` |
| `EXPECTED_CALLER_SA` | обязательна | email service account, которому разрешено звать. Несекретна |
| `SERVICE_AUDIENCE` | обязательна | допустимые `aud` через запятую — адреса этого сервиса. Несекретна |

Обе обязательны: других способов аутентификации не осталось, и сервис без них
не может пустить никого. Падение на старте честнее, чем ответ 403 на всё.

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
- выбирает максимум 50 пунктов верхнего уровня и до 100 подпунктов;
- шлёт подпункты вложенными в свой пункт и не шлёт подпункт без его пункта;
- отдельно выбирает до 10 записей с заметками в пределах 8 000 символов;
- передаёт число намеренно опущенных заметок;
- обрезает title, item names, notes и question до совместимых лимитов;
- применяет 15 AI-запросов на пользователя в UTC-день;
- выпускает Google ID-токен и передаёт его в `Authorization`; всё это происходит только на сервере.

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

Нужен `.env` с `ANTHROPIC_API_KEY`, `EXPECTED_CALLER_SA`, `SERVICE_AUDIENCE`
и, при необходимости, `DEBUG=true`. Локально проверка токена не пройдёт:
подписать его может только Google, а федерация настроена на production. Ручные
запросы к локальному инстансу поэтому упираются в 403 — это ожидаемо, и
проверять контракт нужно тестами.

Bruno collection содержит ручные запросы. Её `secret` — secret variable и не
должен сохраняться в коллекции. Текущий `base_url` указывает на Cloud Run,
поэтому перед ручным запросом всегда явно проверь выбранное окружение.

## Тесты

Команда полного прогона:

```bash
pytest tests/ -v
```

Сейчас `pytest tests/ -v` даёт 31 проверку в `tests/test_insights.py`,
включая два параметризованных теста бюджетов. Покрыты:

- health;
- успешный insight с Anthropic mock;
- неверный и отсутствующий Authorization;
- границы title, items, item names, question и notes;
- нормализация whitespace-only optional text;
- список без записей и список только с общей заметкой;
- сохранение связи item note с записью и status;
- передача `omitted_item_notes`;
- подпункты: вложенность в payload, отсутствие ключа при пустом списке,
  запрос без `sub_items`, влияние на требуемую глубину ответа, поштучный и
  совокупный лимиты, недостижимость второго уровня;
- невозможность закрыть untrusted-data block через пользовательский текст —
  отдельно для полей пункта и подпункта.

Autouse fixture сбрасывает in-memory limiter между тестами. Production
декоратор при этом остаётся активным. Сеть и настоящий Anthropic API в тестах
не используются.

## CI

`.github/workflows/ci.yml` запускается для веток и PR, но устраняет дубли:

- push в `main` проверяется test job из deploy workflow;
- PR из ветки того же репозитория уже покрыт push;
- tests job получает только `test-key` и `test-secret-123`;
- secrets job проверяет SHA-256 архива Gitleaks, затем сканирует полную историю
  с `--redact`;
- workflow token имеет только `contents: read`;
- CI ничего не деплоит.

Gitleaks остаётся отдельной full-history защитой для generic patterns поверх
включённого GitHub Secret Scanning.

## Deployment

`.github/workflows/deploy.yml` запускается на push в `main`.

- `test` устанавливает зависимости и запускает pytest с fake credentials;
- `deploy` зависит от успешного `test`;
- `deploy` привязан к GitHub Environment `production`, который разрешает
  deployment только из `main`;
- только `deploy` получает `id-token: write`;
- GitHub OIDC обменивается через Workload Identity Federation на временные
  права service account
  `github-deployer@project-5b7c1bd1-572b-410d-826.iam.gserviceaccount.com`;
- image публикуется в
  `us-central1-docker.pkg.dev/project-5b7c1bd1-572b-410d-826/smart-lists/insights-api`;
- создаются теги commit SHA и `latest`;
- Cloud Run service `insights-api` в `us-central1` разворачивается по SHA tag.

Long-lived GCP JSON key в GitHub нет. В Cloud Run вне репозитория настраиваются
`ANTHROPIC_API_KEY` (секрет), а также несекретные `EXPECTED_CALLER_SA` и
`SERVICE_AUDIENCE`.

`docker-compose.yml` всё ещё ссылается на
`ghcr.io/kiriu237011/smart-lists-fastapi-service:latest`. Это альтернативный
или legacy способ запуска; активный production pipeline использует Artifact
Registry и не обновляет GHCR image.

## Важные решения

- 2026-08-08: в контракт добавлены подпункты. `items` сохранил прежний смысл —
  записи верхнего уровня, — а подпункты приезжают вложенным `sub_items`.
  Так сервис, ещё не знающий о подпунктах, продолжает работать, а новый payload
  не меняет значения существующих полей. Вложенность ограничена типом:
  `SubItem` не имеет собственного `sub_items`, поэтому проверять глубину не
  нужно. Лимит подпунктов держится отдельно от лимита пунктов: общий счёт
  означал бы разное для разных списков — один длинный блок вытеснял бы из
  контекста половину списка. Бюджет заметок, наоборот, общий на оба уровня,
  иначе вложенность стала бы способом его обойти.
- 2026-07-30: архив Gitleaks проверяется перед распаковкой по закреплённому
  SHA-256 официального release asset; скачанный бинарь не запускается при
  несовпадении checksum.
- 2026-07-30: все сторонние GitHub Actions в CI и deploy закреплены по полным
  commit SHA. Repository policy разрешает только GitHub-owned Actions и Actions
  от verified creators, а также требует SHA pinning. `GITHUB_TOKEN` по умолчанию
  имеет только read-доступ и не может одобрять PR. Версии `v3`/`v7` сохранены в
  комментариях для читаемости и обновления Dependabot.
- 2026-07-30: репозиторий опубликован. `main` защищён repository ruleset:
  изменения проходят через PR и проверки `tests`/`secrets`, force-push и
  удаление запрещены. Approval не требуется, потому что у репозитория один
  участник. GitHub Secret Scanning, Push Protection и CodeQL default setup
  включены.
- 2026-07-30: deploy job привязан к GitHub Environment `production` с branch
  policy только для `main`. Required reviewer отсутствует, потому что у
  репозитория один участник; защиту обеспечивают ruleset, test gate и WIF.
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
