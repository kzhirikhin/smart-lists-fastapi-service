# Память проекта Smart Lists AI Service

> Живой снимок устойчивых знаний о проекте. Перед работой сверяй его с кодом и
> обновляй после существенных изменений.

**Последнее обновление:** 2026-09-03 (`.env` по абсолютному пути, лишние ключи игнорируются)

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
- Cloud Run и Google Cloud задают ingress, TLS, IAM и личность сервиса.

## Актуальный стек

- Python 3.13;
- FastAPI `0.141.1`, Starlette `1.3.1`, Uvicorn `0.52.2`;
- Pydantic `2.12.5` и pydantic-settings `2.15.0`;
- Anthropic SDK `0.121.0` — версия, в которой появился
  `WorkloadIdentityCredentials`;
- SlowAPI `0.1.10`;
- google-auth `2.56.3` и requests `2.34.2` — проверка входящих Google
  ID-токенов и запрос собственного токена у metadata-сервера;
- pytest `9.1.1`, pytest-asyncio `1.4.0` и FastAPI TestClient;
- Docker, Google Artifact Registry и Google Cloud Run;
- GitHub Actions, GitHub OIDC и Google Workload Identity Federation;
- Grype `0.117.0` для deploy-time и еженедельного image scanning.

Руками правятся только `requirements.in` и `requirements-dev.in`; полные
наборы с версиями и SHA-256 каждого артефакта разворачивает pip-compile.
Инструментарий тестов в production-образ не попадает. Python version должна
совпадать в `Dockerfile`, `ci.yml` и `deploy.yml`.

## Карта репозитория

- `app/main.py` — FastAPI app, access log, exception handlers и `/health`;
- `app/core/request_boundary.py` — ранняя аутентификация `/insights` и
  streaming-лимит фактически прочитанного body;
- `app/core/config.py` — env-backed настройки;
- `app/core/caller_auth.py` — проверка вызывающего по Google ID-токену;
- `app/core/anthropic_auth.py` — собственный ID-токен из metadata-сервера и
  учётные данные федерации для Anthropic;
- `app/core/limiter.py` — SlowAPI limiter и извлечение source IP;
- `app/core/logging_config.py` — базовая конфигурация stdout logging;
- `app/models/insights.py` — request/response contract, нормализация и бюджеты;
- `app/routers/insights.py` — rate limit и orchestration после ранней границы;
- `app/services/ai.py` — prompt, сериализация недоверенных данных и Anthropic;
- `tests/` — API-, validation- и prompt-boundary тесты;
- `requirements.in` / `requirements-dev.in` — прямые зависимости, правятся
  руками;
- `requirements.txt` — сгенерированный runtime-набор с хешами, он же
  содержимое образа;
- `requirements-dev.txt` — сгенерированное надмножество: runtime плюс
  инструментарий тестов, для CI и локальной разработки;
- `bruno/Smart Lists API/` — ручные запросы health и insight;
- `.github/workflows/ci.yml` — тесты и full-history Gitleaks;
- `.github/workflows/deploy.yml` — test-gated keyless deployment;
- `.github/workflows/image-scan.yml` — еженедельный и ручной fail-closed scan
  фактически обслуживающих Cloud Run digest;
- `scripts/verify_image_evidence.py` — offline-проверка inspect/rootfs exact
  digest для технического обоснования VEX без запуска контейнера;
- `security/SBOM_RUNBOOK.md` — границы контура и порядок разбора красного
  image-scan;
- `Dockerfile` — production image: multi-stage, в runtime только `app/` и
  установленные пакеты, без pip и без файлов репозитория;
- `docker-compose.yml` — локальный запуск со сборкой образа из этого же
  репозитория, не описание Cloud Run deployment.

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
| request body | не более 100 000 фактически прочитанных байт |
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

ASGI middleware проверяет и заявленный `Content-Length`, и фактически
прочитанные чанки. Поэтому отсутствие заголовка или chunked transfer не
обходит 100 KB. Эта граница работает до JSON parser и Pydantic; содержательные
Pydantic-бюджеты действуют независимо вторым слоем.

## Ключевой поток запроса

1. Web Server Action `getListInsight` проверяет сессию и доступ к списку через
   БД, выбирает ограниченный набор записей и заметок и атомарно применяет лимит
   15 запросов на пользователя в UTC-день.
2. Web backend вызывает `${INSIGHTS_SERVICE_URL}/insights`. В `Authorization`
   едет Google ID-токен, выпущенный через Workload Identity Federation.
3. Cloud Run проверяет право звать по IAM ещё до контейнера. Затем сырой ASGI
   middleware FastAPI повторно проверяет ID-токен до чтения body и ограничивает
   объявленный и фактически прочитанный размер.
4. Pydantic нормализует и валидирует поля и совокупный note budget, после чего
   router применяет дополнительный per-IP rate limit.
5. `get_insight` определяет требуемую глубину ответа по числу записей обоих
   уровней, пересчитывает проверяемые note counters и строит payload:
   подпункты уходят вложенным `sub_items` внутри своего пункта, пустой список
   в payload не выводится.
6. Payload сериализуется в JSON с `ensure_ascii=False`, затем `&`, `<` и `>`
   заменяются на unicode escape sequences.
7. JSON помещается в единственный блок `<untrusted_user_data_json>`.
8. Асинхронный Anthropic client вызывает модель
   `claude-haiku-4-5-20251001`. Если кешированный access-токен истёк, клиент
   сначала берёт у metadata-сервера ID-токен и обменивает его — примерно раз в
   десять минут, а не на каждый запрос.
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

### Аутентификация в Anthropic

Обратное направление устроено симметрично: сервис предъявляет Anthropic не
ключ, а собственный Google ID-токен и обменивает его на access-токен на десять
минут (`app/core/anthropic_auth.py`). Ключа API у сервиса нет — ни в
переменных окружения, ни в образе, ни в ревизиях Cloud Run.

- Токен запрашивается у metadata-сервера с `format=full`. Без этого параметра
  в токене нет claim `email`, а правило федерации сверяет его вместе с `sub`;
  проверка закреплена тестом, потому что ошибка проявляется только в
  production и выглядит как немотивированный отказ.
- `credentials=` передаётся в клиент явно, и SDK из-за этого не читает
  `ANTHROPIC_API_KEY` вовсе: забытая переменная не может подменить способ
  входа. Это тоже закреплено тестом — поведение зависит от внутреннего правила
  библиотеки.
- `base_url=` передаётся явно по той же причине: без аргумента SDK берёт адрес
  из `ANTHROPIC_BASE_URL`, и одна переменная в ревизии увела бы весь поток
  вместе с токеном в заголовке `Authorization` на чужой хост — без нового
  образа, то есть мимо хешей зависимостей, скана и выкладки по digest.
  Закреплено парой тестов: один требует, чтобы переменная не двигала клиент,
  второй проверяет на клиенте без аргумента, что механизм подмены вообще жив.
- Правило на стороне Anthropic привязано к `sub` и `email` service account
  `insights-api-runtime`. Смена личности сервиса ломает аутентификацию, поэтому
  `deploy.yml` задаёт `--service-account` явно.
- Scope токена — `workspace:developer`, столько же, сколько давал прежний ключ.
  Сузить не удалось: `workspace:inference` в правиле недоступен, а запрос
  такого scope при обмене сервер молча игнорирует (проверено 2026-08-10).

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
- `anthropic.APIStatusError` преобразуется в generic `502`; в error log идут
  только status, тип и `request_id`, но не `exc.message` с телом ответа vendor.
- `ValueError`, включая отсутствие text block, преобразуется в generic `500`.
- Остальные исключения обрабатываются стандартным механизмом FastAPI.

### Границы текущих защит

- SlowAPI использует память процесса; при нескольких Cloud Run instances лимит
  не общий.
- `_get_real_ip` доверяет первому `X-Forwarded-For`. Это корректно только за
  контролируемым ingress. При прямом доступе клиент мог бы влиять на ключ
  limiter.
- Репозиторий не описывает Cloud Run ingress policy; это внешняя
  инфраструктура. Runtime secrets описывать больше нечем: их нет.
- `DEBUG=true` публикует OpenAPI UI и допустим только локально.
- Контейнер работает под `appuser` (uid 10001). Долгоживущих секретов внутри
  не осталось, но доступ к metadata-серверу есть у любого процесса контейнера
  независимо от UID: код, исполняемый внутри, может получить токен сервиса.
  Граница защиты — сам контейнер, а не пользователь в нём.
- Из runtime-образа удалён pip: инструмент установки пакетов рядом с сетевым
  доступом сокращал бы путь от RCE ко второй стадии. Зависимости ставит
  отдельная сборочная стадия. Первый fail-closed run `33238953019` от
  2026-08-29 проверил рабочий digest `sha256:990201…9263` и нашёл 7 Critical +
  20 High package/CVE совпадений (6 и 15 уникальных CVE) в базовых
  Debian-пакетах: `perl-base`, glibc, ncurses, SQLite, ACL и gzip. У всех fix
  state `not-fixed` или `wont-fix`; исключений нет.
- Grype в `deploy.yml` остаётся неблокирующей дельтой момента сборки и использует
  `--only-fixed`. Независимый `image-scan.yml` раз в неделю и вручную берёт из
  Cloud Run все revisions с трафиком или tag, разрешает их только в ожидаемые
  `${IMAGE}@sha256:<digest>` и сканирует без `--only-fixed`. Сырой JSON передаёт
  `scripts/evaluate_image_scan.py`: High/Critical остаются блокирующими, кроме
  exact CycloneDX VEX `not_affected` или действующего временного waiver.
  Неактуальная база CVE, пустой список целей, повреждённая политика и любая
  техническая ошибка делают job красной. Raw и policy JSON сохраняются 30 дней.
- `groups` — до 20 строк по 100 символов свободного текста, попадающего в
  prompt. С 2026-08-14 поле заполняется web-приложением; для вызывающего мимо
  приложения оно, как и остальные поля, ограничено только Pydantic.

## Конфигурация

`Settings` читает `.env` локально и environment variables во всех средах. Путь
к `.env` абсолютный и привязан к `app/core/config.py`, а не к текущему каталогу
процесса; лишние ключи файла игнорируются (`extra="ignore"`). Причина — A77:
относительный путь позволял прочитать посторонний `.env`, а запрет лишних
ключей приводил к тому, что pydantic печатал их значения в тексте ошибки.

| Переменная | Обязательность | Назначение |
| --- | --- | --- |
| `DEBUG` | необязательна | включает `/docs`, `/redoc` и `/openapi.json`, default `false` |
| `EXPECTED_CALLER_SA` | обязательна | email service account, которому разрешено звать. Несекретна |
| `SERVICE_AUDIENCE` | обязательна | допустимые `aud` через запятую — адреса этого сервиса. Несекретна |
| `ANTHROPIC_FEDERATION_RULE_ID` | обязательна | `fdrl_*` — правило федерации. Несекретна |
| `ANTHROPIC_ORGANIZATION_ID` | обязательна | UUID организации Anthropic. Несекретна |
| `ANTHROPIC_SERVICE_ACCOUNT_ID` | обязательна | `svac_*` — личность на стороне Anthropic. Несекретна |
| `ANTHROPIC_WORKSPACE_ID` | обязательна | `wrkspc_*` — workspace для токена. Несекретна |

Секретов в списке нет ни одного: конфигурация сервиса состоит из
идентификаторов и адресов. Все обязательны — без них сервис не может ни
пустить вызывающего, ни обратиться к Anthropic, и падение на старте честнее,
чем ответ ошибкой на каждый запрос.

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
- шлёт до 20 групп, в которых состоит список, и только группы вызывающего:
  группы персональные, и чужая классификация расшаренного списка в контекст
  попасть не должна;
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
python -m pip install --require-hashes -r requirements-dev.txt
uvicorn app.main:app --reload
```

Нужен `.env` с `EXPECTED_CALLER_SA`, `SERVICE_AUDIENCE`, четырьмя
`ANTHROPIC_*` идентификаторами и, при необходимости, `DEBUG=true`. Локально не
работает ни одна из двух сторон аутентификации: входящий токен подписывает
только Google, а исходящий требует metadata-сервера, которого вне Google Cloud
нет. Ручные запросы к локальному инстансу упираются в 403 — это ожидаемо, и
проверять контракт нужно тестами.

Bruno collection содержит ручные запросы. Её `secret` — secret variable и не
должен сохраняться в коллекции. Текущий `base_url` указывает на Cloud Run,
поэтому перед ручным запросом всегда явно проверь выбранное окружение.

## Тесты

Команда полного прогона:

```bash
pytest tests/ -v
```

Сейчас прогон даёт 180 проверок: 67 в `tests/test_supply_chain.py`, 47 в
`tests/test_insights.py`, включая два параметризованных теста бюджетов, 31 в
`tests/test_image_evidence.py`, 14 в `tests/test_scan_policy.py`, 8 в
`tests/test_attestation_certificate.py`, 7 в `tests/test_outbound_calls.py` и 6
в `tests/test_anthropic_auth.py`.

`test_supply_chain.py` — статические контракты цепочки поставок, аналог набора
`security-static` из web-репозитория. Отдельного gate здесь нет, поэтому они
живут в обычном прогоне pytest, который уже является required check. Проверяют:
закрепление всех `uses:` полным SHA с комментарием версии; совпадение прямых
версий `.in` ↔ `.txt` вместе с сохранностью заголовка pip-compile и хешей;
наличие `--require-hashes` и `--only-binary=:all:` у каждой установки в
workflow и в `Dockerfile`; recurring scan дополнительно фиксирует вызов exact
policy evaluator, offline runtime evidence без `docker run` и раздельное
сохранение raw/policy/evidence отчётов. Базовые
утверждения были истинны и до появления тестов — закрепляется не их появление,
а то, что они не станут ложными молча.

`test_outbound_calls.py` (2026-09-01) той же формой закрывает A56: обходит
`app` и требует, чтобы каждый сетевой вызов лежал в allowlist с причиной —
`requests`, `httpx`, `urllib`, `aiohttp`, `socket`, конструктор клиента
Anthropic, транспорт google-auth и `verify_oauth2_token`. Раньше закреплены
были адреса трёх существующих вызовов, но не их число, поэтому четвёртый вызов
с адресом из окружения прогон бы не покрасил. Зеркало `outbound-requests.test.ts`
из web-репозитория.

Покрыты:

- health;
- успешный insight с Anthropic mock;
- неверный и отсутствующий Authorization;
- отказ без токена до Pydantic даже для malformed body;
- ранний отказ для большого `Content-Length` и для chunked body без него;
- отсутствие тела ошибки Anthropic в логах при сохранении `request_id`;
- границы title, items, item names, question и notes;
- нормализация whitespace-only optional text;
- список без записей и список только с общей заметкой;
- сохранение связи item note с записью и status;
- передача `omitted_item_notes`;
- подпункты: вложенность в payload, отсутствие ключа при пустом списке,
  запрос без `sub_items`, влияние на требуемую глубину ответа, поштучный и
  совокупный лимиты, недостижимость второго уровня;
- отсутствие у модели любых возможностей: набор аргументов `messages.create`
  проверяется целиком, поэтому `tools`, `mcp_servers`, `container` или betas
  нельзя добавить незаметно;
- невозможность закрыть untrusted-data block через пользовательский текст —
  отдельно для полей пункта и подпункта;
- запрос собственного ID-токена: `format=full`, audience и заголовок
  metadata-сервера; отказ metadata-сервера не превращается в пустой токен;
- клиент Anthropic аутентифицируется федерацией, а выставленная
  `ANTHROPIC_API_KEY` этого не меняет;
- адрес Anthropic не задаётся окружением: выставленная `ANTHROPIC_BASE_URL` не
  двигает клиент, и отдельный контрольный тест на клиенте без `base_url=`
  фиксирует, что механизм подмены в SDK жив, а не отмер.
- VEX подавляет только точное CycloneDX `not_affected` с evidence/review;
  остальные states, blanket package, отсутствие evidence и пересечение с
  waiver отвергаются; активный waiver работает, истёкший — уже нет, а срок
  больше 30 дней запрещён.

Autouse fixture сбрасывает in-memory limiter между тестами. Production
декоратор при этом остаётся активным. Сеть и настоящий Anthropic API в тестах
не используются.

## CI

`.github/workflows/ci.yml` запускается для веток и PR, но устраняет дубли:

- push в `main` проверяется test job из deploy workflow;
- PR из ветки того же репозитория уже покрыт push;
- tests job получает только заведомо нерабочие placeholder-идентификаторы;
- secrets job проверяет SHA-256 архива Gitleaks, затем сканирует полную историю
  с `--redact`;
- dependency-review job работает только на `pull_request`, через dependency
  graph API и без исполнения кода PR: `fail-on-severity: high`, все scopes,
  `deny-licenses: GPL-2.0, GPL-3.0, AGPL-3.0, SSPL-1.0`;
- workflow token имеет только `contents: read`;
- CI ничего не деплоит.

Gitleaks остаётся отдельной full-history защитой для generic patterns поверх
включённого GitHub Secret Scanning.

Dependency Review появился 2026-08-28. До этого SCA-гейта на PR не было вовсе,
а Dependabot сканирует только ветку по умолчанию — то есть между внесением
уязвимой зависимости и её выкладкой в Cloud Run не было ни одного сигнала.
В web-репозитории такой гейт стоял с самого начала, и разница ничем не
объяснялась.

Ruleset `Protect main` выровнен с web-репозиторием 2026-08-28: PR обязателен,
`deletion` и `non_fast_forward` запрещены, bypass-акторов нет, контексты
`tests` и `secrets` привязаны к GitHub Actions через `integration_id`, `strict`
требует актуальной базы, CodeQL блокирует мерж по порогу errors/high-or-higher.
`dependency-review` добавляется в required checks только после того, как job
отчитался хотя бы раз: контекст, который никогда не приходит, блокирует все PR.

## Deployment

`.github/workflows/deploy.yml` запускается на push в `main`, но не на любой:
фильтр `paths` — allowlist входов образа (`Dockerfile`, `.dockerignore`,
`requirements.txt`, `app/**`), самого workflow и исполняемого им
`scripts/verify_attestation_certificate.py`. Состав сверяется с `COPY` из
Dockerfile тестом `TestDeployTriggers`, поэтому новый вход образа расширяет
требование сам.

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
- образ помечается тегом commit SHA; мутабельный `latest` больше не
  публикуется;
- после push Syft 1.51.0 строит CycloneDX JSON 1.6 по `${IMAGE}@${digest}`;
  workflow проверяет формат, непустой состав, версию Syft и совпадение
  `metadata.component.version` с digest, затем прикрепляет файл к этой версии
  образа в Artifact Registry;
- SBOM attachment блокирует deploy при технической ошибке и создаётся
  идемпотентно с media type `application/vnd.cyclonedx+json`. Отдельного архива
  нет: cleanup образа удаляет и attachment;
- первый production run `33251609209` от 2026-08-29 создал attachment для
  `sha256:b5e2b41c…41a6` до успешного Cloud Run deploy. Файл скачан обратно:
  CycloneDX 1.6, Syft 1.51.0, 2858 components, 1 083 779 байт; его
  `metadata.component.version` точно совпадает с target digest;
- перед выкладкой образ сканируется grype (`--only-fixed`); шаг намеренно
  не блокирующий — см. раздел о границах защит;
- Cloud Run service `insights-api` в `us-central1` разворачивается по digest
  собранного образа, с явными `--service-account` и `--port 8000`.

BuildKit provenance включён как SLSA v1 `mode=max`. Production run
`33312038124` успешно собрал commit
`82af49199223f1b2b7c5821d732b5e801bc65539`, проверил metadata и развернул
`sha256:e613b27e…b5b281` в ревизию `insights-api-00047-hff`; независимая проверка
Cloud Run подтвердила 100% трафика на тот же digest. До SBOM и Cloud Run
workflow читает exact
`${IMAGE}@${DIGEST}` через `docker buildx imagetools inspect` и fail-closed
требует BuildKit build type, непустые materials/LLB и встроенный Dockerfile.
Аудит подтвердил отсутствие `ARG`, `build-args` и secret inputs, поэтому
подробный документ не получает чувствительные значения.

Этап 3 реализован и подтверждён в production: `actions/attest` выпускает keyless
SLSA v1 attestation exact digest через GitHub OIDC/Sigstore, а закреплённый по
версии и checksum GitHub CLI до SBOM/deploy проверяет trusted root, подпись,
subject, signer workflow/digest, source ref/digest и запрет self-hosted runner.
Из уже проверенного X.509 дополнительно требуются Environment `production`,
event `push`, runner `github-hosted` и repository ID `1199475908`. Новых
долгоживущих ключей, service account и GCP IAM-прав нет. Production run
`33384972241` проверил все эти условия для commit `ac1d92f…`, прикрепил SBOM и
развернул exact `sha256:e727018e…3cd9701`; ревизия `insights-api-00048-dff`
получила 100% трафика. Полный контракт хранится в разделе provenance
`security/SBOM_RUNBOOK.md`.

Этап 4 завершил эксплуатационный контур. Еженедельный/ручной
`image-scan.yml` до CVE-анализа проверяет provenance всех traffic/tagged
revisions с прежней read-only identity. Cloud Run показывает дочерний
`linux/amd64` manifest (`sha256:498cd37a…5f1a70`), тогда как attestation и SBOM
относятся к build output — родительскому OCI index
`sha256:e727018e…3cd9701`. Workflow fail-closed находит ровно один tagged OCI
index, проверяет точное членство serving manifest в его raw JSON, затем
проверяет подпись и claims parent index; оба JSON сохраняются на 30 дней.
Operational run `33391706750` подтвердил эту цепочку. В самом run отдельный
CVE-policy нового serving manifest заблокировал Critical=7 и High=20 при VEX=0
и waiver=0; runtime evidence при этом прошёл. Последующий review PR №52 сверил
все 21 CVE с актуальными Debian advisory и exact evidence этого digest. Новый
CycloneDX VEX содержит 27 точных statements. Post-merge operational run
`33498396730` повторно подтвердил provenance parent index, exact runtime
evidence 22/22 и 21/21 claims; policy получил Critical=7/High=20 до VEX,
подавил VEX=27 при waiver=0 и завершился с Critical=0/High=0, `Gate: PASS`.

Reviewed VEX для предыдущего `sha256:082760…52fe3` к новому serving digest не
переносится. Для `sha256:498cd37a…5f1a70` создан отдельный VEX в PR №52 после
нового review exact rootfs и advisory; его statements не применяются ни к
предыдущему, ни к следующему digest.

`.github/workflows/image-scan.yml` использует отдельную keyless identity
`github-image-scanner@project-5b7c1bd1-572b-410d-826.iam.gserviceaccount.com`.
WIF разрешён только repository ID `1199475908` из `main`; у identity есть
project-level `roles/run.viewer` и repository-level
`roles/artifactregistry.reader` только на `smart-lists`. Прав deploy/write,
доступа к runtime-SA, БД и пользовательским данным нет. `github-deployer`
может назначать только `insights-api-runtime`: лишний `serviceAccountUser` на
неиспользуемый Default Compute SA удалён 2026-08-29.
Новой identity для SBOM нет: `github-deployer` уже имел repository write для
push образа, а эта роль включает создание и чтение attachments.

Перед Grype recurring workflow скачивает каждый обслуживающий exact digest и
без запуска контейнера читает его конфигурацию и rootfs через `docker image
inspect` + `docker create/export`. Fail-closed скрипт сверяет digest,
архитектуру `amd64`, пользователя `appuser`, точный Uvicorn CMD, Debian-пакеты,
наличие релевантных Perl-модулей и AST фактических Python-исходников в
`/app/app`. Для glibc он дополнительно без исполнения разбирает undefined
dynamic symbols всех ELF64-файлов и ищет условия трёх advisory во всём exact
rootfs и runtime-поверхности `/app` + `/usr/local`: DNS-print symbols,
`%mc` с шириной больше 1024 и путь `ungetwc`/`libstdc++`. JSON evidence
сохраняется рядом с raw/policy отчётами. Он содержит поддерживающие проверки
для 21 CVE, но ничего не подавляет автоматически: `checksPassed` — вход для
отдельного advisory-review и exact CycloneDX VEX.

Репозиторная политика исключений не требует внешнего сервиса и новых прав.
`security/vex/<digest>.cdx.json` содержит CycloneDX 1.6 только для доказанного
`not_affected`: exact CVE, package name/version/purl и image digest, evidence и
review PR. `security/waivers.json` отдельно описывает принятый реальный риск:
owner/approver, reason, remediation plan, evidence и срок максимум 30 дней.
Истёкшая запись, любой другой VEX state и wildcard не подавляют. Production run
`33297043344` создал SBOM и развернул
`sha256:082760…52fe3`; контрольный image-scan `33297174858` подтвердил для этого
serving digest runtime evidence `PASS`: 18/18 checks, 18/18 candidate claims,
`amd64`, `appuser`, 15 Python-файлов и отсутствие запуска контейнера. После
advisory-review exact VEX в PR #38 подавляет 21 package match по 18 CVE:
недостающие Perl-модули, недостижимые CLI/SQLite/ACL/Perl paths и одну
32-битную Perl-уязвимость в `amd64`. После merge evidence PR #39 run
`33299518793` тем же способом подтвердил 22/22 checks, 21/21 candidate claims и
разбор 754 ELF exact rootfs. Отдельный review PR #40 добавил шесть exact
statements для трёх glibc CVE. Финальный post-merge run `33308851706` проверил
тот же serving digest: evidence 22/22, claims 21/21, до политики Critical=7 и
High=20, подавлено VEX=27 и waiver=0, осталось Critical=0 и High=0, `Gate:
PASS`. Истёкших waiver match нет. Raw Grype JSON, policy JSON,
Markdown-сводка и evidence JSON сохранены одним artifact на 30 дней.

`Gate: BLOCKED` и `Gate: PASS` — статусы конкретного operational image-scan, а
не required PR check или release gate. Policy-only merge автоматически
повторяет scan того
же production digest и исключён из `deploy.yml`, иначе новый build немедленно
сделал бы exact VEX/waiver устаревшим. Полный порядок реакции хранится в
`security/SBOM_RUNBOOK.md`. Dependency-Track для одного контейнера не
внедряется; Next.js/Vercel artifact SBOM и provenance остаются вне этого
контура.

Long-lived GCP JSON key в GitHub нет. В Cloud Run вне репозитория
настраиваются `EXPECTED_CALLER_SA`, `SERVICE_AUDIENCE` и четыре `ANTHROPIC_*`
идентификатора — все несекретные. Сервис выполняется под
`insights-api-runtime@project-5b7c1bd1-572b-410d-826.iam.gserviceaccount.com`,
и `deploy.yml` передаёт эту личность явно.

`docker-compose.yml` собирает образ локально (`build: .`) и служит только для
проверки того, что процесс поднимается. Раньше он тянул
`ghcr.io/kiriu237011/…:latest`, но этого аккаунта на GitHub больше не
существует: освободившееся имя владельца может занять посторонний и подставить
произвольный образ на машину разработчика. Активный production pipeline
использует Artifact Registry и GHCR не трогает.

### Retention образов в Artifact Registry

Cleanup policy репозитория `smart-lists` состоит из трёх правил: KEEP 20 самых
новых версий, KEEP всё моложе 30 дней, DELETE всё старше. С 2026-09-01 она
работает боевым режимом; до этого дня стоял `cleanupPolicyDryRun`, при котором
policy только писала `BatchDeleteVersions` в audit log и ничего не удаляла.

`keepCount` считает **версии пакета, а не образы**. Один deploy создаёт 3–4
версии: OCI index, дочерний `linux/amd64` manifest, attestation и SBOM —
attachment занимает собственную версию, и её видно в поле `ociVersionName`.
Поэтому 20 — это примерно пять последних выкладок, а не двадцать; прежнее
значение 10 давало около двух с половиной и было выбрано в расчёте на образы.

Значение важно не только для глубины отката. Пока выкладки идут чаще раза в
месяц, работающий образ удерживает `keep-fresh`; при паузе дольше 30 дней
единственным, что оставляет его в реестре, остаётся `keepCount`.

Удаление версии необратимо уносит её SBOM и attestation: отдельного архива нет
по построению — см. `security/SBOM_RUNBOOK.md`. На `image-scan.yml` это не
влияет: он берёт только traffic/tagged revisions, а их образы всегда свежие.

Policy применяется вручную, CI её не накатывает. Флагов cleanup-policy в
`gcloud artifacts repositories update` нет (проверено на 581.0.0), поэтому
единственный путь — REST:

```bash
curl -X PATCH \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  --data @cleanup-policy.json \
  "https://artifactregistry.googleapis.com/v1/projects/${PROJECT_ID}/locations/${REGION}/repositories/${REPOSITORY}?updateMask=cleanupPolicies,cleanupPolicyDryRun"
```

```json
{
  "cleanupPolicies": {
    "keep-recent-versions": {
      "id": "keep-recent-versions",
      "action": "KEEP",
      "mostRecentVersions": { "keepCount": 20 }
    },
    "keep-fresh": {
      "id": "keep-fresh",
      "action": "KEEP",
      "condition": { "newerThan": "2592000s", "tagState": "TAG_STATE_UNSPECIFIED" }
    },
    "delete-stale": {
      "id": "delete-stale",
      "action": "DELETE",
      "condition": { "olderThan": "2592000s", "tagState": "TAG_STATE_UNSPECIFIED" }
    }
  },
  "cleanupPolicyDryRun": false
}
```

## Важные решения

- 2026-09-03: `.env` читается по абсолютному пути, лишние ключи игнорируются.
  Относительный `".env"` означал не «файл сервиса», а «файл рядом с рабочим
  каталогом»: скрипт из соседнего репозитория подсунул сервису чужой `.env`.
  Дороже обошлась вторая половина — при `extra="forbid"` pydantic перечисляет
  посторонние ключи в тексте `ValidationError` вместе со значениями, то есть
  печатает секреты в лог. Production это не затрагивало (в Cloud Run `.env`
  нет, а несовпадающие переменные окружения в модель не передаются), но
  ошибка конфигурации не должна быть способом раскрыть секрет. Цена решения:
  опечатка в имени переменной внутри локального `.env` теперь не заметна —
  значение молча не применится; отсутствие обязательного по-прежнему роняет
  старт, и это закреплено отдельным тестом. Подробности — A77.
- 2026-09-03: модель остаётся `claude-haiku-4-5-20251001`; альтернативы
  проверены и отклонены. На наборе из 16 сценариев, покрывающих все три ветки
  `depth_instruction`, замерены цена, латентность и тексты ответов: Haiku ≈ $3.4
  на тысячу инсайтов при 5.8 с, Sonnet 5 ≈ $7.9 при 9.3 с, Sonnet 4.6 ≈ $12.3
  при 13.3 с (предыдущее поколение дороже текущего: $3/$15 против $2/$10).
  Качественного выигрыша, оправдывающего множитель, у старших моделей не
  нашлось. Размышления на этой задаче не окупаются ни на одной модели: adaptive
  thinking сам от них отказывается — выходных токенов не больше, чем без него, —
  а принудительный бюджет на Haiku почти удваивает расход, не меняя ответа.
  Переключатель `INSIGHTS_MODEL`, заведённый ради этой проверки, снят вместе с
  ней; если сравнение понадобится снова, см. PR №60 и его revert. Отдельная
  находка, к выбору модели не относящаяся: правило system prompt «отвечай на
  языке `user_message`» проигрывает языковому фону содержимого примерно в
  половине прогонов, независимо от модели, — это слабое место prompt, и оно не
  исправлено.
- 2026-09-02: выкладка отбирает пути allowlist'ом, а не перечнем исключений.
  Прежний `paths-ignore` перечислял известные на момент написания пути, тогда
  как требование звучит про все остальные — те, которых ещё нет. Проявилось
  это дорого: тестовый PR №57 добавил `tests/test_outbound_calls.py`, файла не
  оказалось в перечне, deploy пересобрал production, и 27 exact VEX-statements
  предыдущего digest перестали к нему относиться. Allowlist переворачивает
  задачу в ту, у которой есть источник факта: входы образа выводятся из `COPY`
  в Dockerfile, и `TestDeployTriggers` сверяет список с ним, а не с копией в
  тесте. Цена решения названа честно: промах allowlist даёт «не задеплоили
  нужное» вместо «задеплоили лишнее» — тише и опаснее, но именно этот промах
  тест и ловит, чего для denylist сделать нельзя в принципе.
- 2026-09-01: cleanup policy реестра выведена из dry-run, `keepCount` поднят
  с 10 до 20. Причина не в объёме, а в единице измерения: `keepCount` считает
  версии пакета, а SBOM и attestation занимают версии наравне с образом, из-за
  чего «10 последних версий» означали около двух с половиной выкладок. Порог
  выбран так, чтобы при паузе в деплоях дольше 30 дней в реестре гарантированно
  оставалось около пяти последних выкладок и при этом репозиторий укладывался
  в бесплатные 0,5 GB. Policy остаётся ручной внешней настройкой: CI её не
  накатывает и тестом она не закреплена — это осознанный остаток, записанный
  как A73 в `THREAT_MODEL.md` репозитория `smart-lists`.
- 2026-08-30: для production digest `sha256:082760…52fe3` после сверки exact
  Grype match, официальных Debian advisory и runtime evidence reviewed VEX
  покрывает 21 CVE / 27 package match. Он не утверждает, что версии пакетов
  исправлены: уязвимый код отсутствует, требуемый runtime path недостижим либо
  не совпадает архитектура. Для трёх glibc CVE отдельно проверены 754 ELF и
  точные условия advisory; waiver в решение не включён.
- 2026-08-30: VEX по недостижимому runtime path должен опираться на байты exact
  production digest, а не на checkout или предположение о базовом образе.
  `image-scan.yml` поэтому сохраняет воспроизводимый inspect/rootfs evidence,
  не исполняя образ. Автоматический PASS не равен `not_affected`: решение и
  CycloneDX VEX остаются отдельным review. Для трёх glibc-находок fail-closed
  контроль проверяет именно условия официальных advisory и все ELF exact
  rootfs; сам по себе этот контроль их не закрывает. Новых зависимостей,
  внешних сервисов и IAM-прав нет.
- 2026-08-30: строгий image-scan остаётся operational gate, а не автоматическим
  запретом merge/deploy. Policy-only изменения запускают его по push в `main`,
  но не пересобирают image; mixed runtime+policy PR по-прежнему создаёт новый
  digest, и старое exact-исключение на него не переносится. Dependency-Track,
  Next.js/Vercel SBOM и provenance в контур не входят; триггеры пересмотра
  зафиксированы в `security/SBOM_RUNBOOK.md`.
- 2026-08-30: для отдельной задачи provenance определён контракт; BuildKit
  metadata реализована этапом 2, но полный криптографический контроль ещё нет.
  Production-образ должен иметь BuildKit SLSA provenance `mode=max` и keyless
  GitHub Artifact Attestation exact digest. Доверенная
  identity ограничена репозиторием, `deploy.yml`, `push` в `main`, Environment
  `production` и текущим commit SHA; проверка до Cloud Run deploy fail-closed.
  Долгоживущего signing key и отдельной service account не будет. Next.js/Vercel
  остаётся вне контура, поскольку полный финальный artifact нам не принадлежит.
- 2026-08-30: этап 2 provenance реализован и проверен в production. Run
  `33312038124` выпустил для commit `82af491…` BuildKit SLSA v1 `mode=max`,
  structural gate проверил exact `sha256:e613b27e…b5b281` до SBOM и Cloud Run,
  а ревизия `insights-api-00047-hff` получила 100% трафика на тот же digest.
  Registry-документ содержит BuildKit build type, resolved dependencies,
  внутренний LLB, Dockerfile и точный VCS revision. Статический контракт
  запрещает незаметно добавить `ARG`/build secret inputs без пересмотра риска
  раскрытия. Подписи и проверки GitHub signer identity на этом этапе ещё нет.
- 2026-08-31: этап 3 provenance реализован и production-проверен. Exact build
  digest подписывается `actions/attest` через GitHub OIDC/Sigstore без
  долговременного ключа; GitHub CLI 2.98.0 с закреплённым checksum fail-closed
  проверяет подпись/trusted root, subject, workflow и source identity, а также
  сертификатные claims `production`, `push`, `github-hosted` и стабильный
  repository ID. Новая GitHub permission ограничена выпуском attestation;
  `packages: write`, новая GCP identity и новые GCP-права не добавлены. Первый
  run `33384270596` fail-closed остановился до SBOM/deploy из-за неверного пути
  к сертификатным полям; исправленная DER-проверка закреплена негативными
  тестами. Run `33384972241` для commit `ac1d92f…` проверил keyless attestation,
  создал SBOM и развернул exact `sha256:e727018e…3cd9701` в ревизию
  `insights-api-00048-dff` со 100% трафика.
- 2026-08-31: этап 4 provenance завершён. Recurring read-only scanner проверяет
  все traffic/tagged revisions и различает подписанный OCI index от фактически
  обслуживаемого `linux/amd64` manifest: требует ровно одну exact parent-child
  связь, затем проверяет keyless attestation parent. Run `33391706750`
  подтвердил `sha256:e727018e…3cd9701` → `sha256:498cd37a…5f1a70` и provenance
  `PASS`. Live-негативные проверки отклонили ложный signer, подменённый digest и
  старый образ без attestation. Следующий CVE gate независимо дал `BLOCKED`
  (Critical=7, High=20, VEX=0, waiver=0); это отдельная задача разбора нового
  exact digest, а не незавершённый provenance.
- 2026-08-29: VEX не используется как эвфемизм для принятого риска. Только
  доказанный `not_affected` живёт в CycloneDX; реальная временная уязвимость —
  в отдельном waiver максимум на 30 дней. Grype 0.117.0 напрямую принимает
  OpenVEX/CSAF, но не выбранный CycloneDX VEX, поэтому stdlib evaluator
  сопоставляет его с сырым JSON Grype и не может подавить техническую ошибку.
  Новых зависимостей, IAM identities и внешних сервисов нет.
- 2026-08-29: SBOM создаётся из уже опубликованного immutable image digest, а
  не из checkout или requirements-файла, поэтому включает финальный Debian-слой.
  Формат — CycloneDX JSON 1.6, инструмент — Syft с закреплёнными версией и
  checksum. Attachment живёт столько же, сколько target image; отдельная
  история удалённых образов сознательно не хранится. SBOM не подписан и не
  доказывает происхождение сборки: provenance остаётся отдельной задачей.
- 2026-08-11: независимый аудит подтвердил два дефекта границы `/insights`:
  проверка токена внутри endpoint происходила после разбора body, а лимит
  доверял только `Content-Length` и обходился chunked-потоком. Проверки
  перенесены в сырой ASGI middleware до маршрутизации; он считает реальные
  байты. Тем же аудитом `exc.message` исключён из Anthropic error log, потому
  что SDK строит его из полного vendor response. `click` обновлён до 8.3.3:
  advisory относился к неиспользуемому здесь `click.edit()` и не давал
  удалённого exploit-path, но уязвимая версия больше не закреплена.
- 2026-08-10: ключ Anthropic заменён workload identity federation. Прежний
  ключ был предъявительским секретом: он лежал в переменной окружения, попадал
  в каждую ревизию Cloud Run и работал у любого, кто его увидел. Теперь сервис
  предъявляет подписанный Google токен своей личности и получает доступ на
  десять минут, а выпустить такой токен можно только изнутри контейнера.
  Ротировать больше нечего — секрета не осталось ни одного. Цена решения:
  аутентификация зависит от metadata-сервера и от того, что личность сервиса
  не меняется молча.
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
