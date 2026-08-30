# Эксплуатация SBOM и image scan

Этот runbook описывает эксплуатационный контур для production-образа
`insights-api`. Владелец контура — владелец репозитория FastAPI. Источник
операционного состояния — GitHub Actions workflow `Scan deployed Cloud Run
images`; Artifact Registry хранит опись, но не принимает решения о риске.

## Что входит в контур

| Часть | Назначение | Блокирует |
|---|---|---|
| CycloneDX SBOM attachment | Опись Python- и системных пакетов конкретного image digest | Deploy, если SBOM нельзя создать, проверить или прикрепить |
| Grype в `deploy.yml` | Быстрая информационная дельта исправимых CVE новой сборки | Ничего: шаг имеет `continue-on-error` |
| `image-scan.yml` | Еженедельная, ручная и policy-triggered проверка всех traffic/tagged Cloud Run digest | Свой workflow при High/Critical или технической ошибке |
| Runtime evidence | Воспроизводимые факты о конфигурации, пакетах и путях исполнения exact digest без запуска контейнера | Тот же workflow при несовпадении или технической ошибке |
| CycloneDX VEX | Доказанный `not_affected` для одной exact-находки | Ничего сам по себе; применяется policy evaluator |
| Временный waiver | Явное принятие реального риска максимум на 30 дней | Ничего сам по себе; применяется policy evaluator |

`Gate: BLOCKED` относится к конкретному image-scan run. Это operational alert,
а не required check PR и не release gate: коммиты, зелёный PR и следующий
deploy он автоматически не запрещает. Красный run при этом нельзя считать
успехом или закрывать пустым ignore — он остаётся видимым до исправления,
доказанного VEX либо явно принятого временного waiver.

## Как разбирать красный run

1. Открыть failed run `Scan deployed Cloud Run images` и его job summary.
2. Скачать artifact `grype-serving-image-reports-<run id>`. Для каждого digest
   там находятся `*-raw.json`, `*-policy.json`, `*-summary.md` и
   `*-evidence.json`.
3. Разделить два класса отказа:
   - `Gate: ERROR`, `Evidence: ERROR` или exit code `2` — сбой Grype, базы,
     GCP, Docker, JSON, policy либо чтения образа. Исключение запрещено:
     исправить техническую причину и повторить run;
   - `Evidence: FAIL` или exit code `1` у runtime evidence — факты exact image
     не соответствуют ожидаемым. VEX по этим фактам запрещён: сначала разобрать
     расхождение и повторить run;
   - `Gate: BLOCKED` или exit code `1` — после политики остались High/Critical.
     Разбирать массив `remaining` из policy JSON.
4. Для каждой оставшейся exact-находки выбрать ровно один путь:
   - обновить базовый образ, прямую или транзитивную зависимость и пересобрать;
   - оформить CycloneDX VEX, только если exploit path проверен и доказан
     `not_affected`;
   - оформить временный waiver, если уязвимость реальна, исправления сейчас нет
     либо немедленная замена создаёт больший риск;
   - оставить run красным, если ни одно решение пока не обосновано.
5. Все VEX/waiver проходят отдельный PR. Точные поля и примеры описаны в
   `security/vex/README.md`.
6. После merge policy-only изменения автоматически запускают image-scan, но
   не пересобирают образ. Успешное закрытие подтверждается новым run по тому же
   digest; зелёный локальный запуск недостаточен.

Если PR одновременно меняет runtime-код и policy, deploy выполняется как
обычно и создаёт новый digest. Старое exact-исключение к нему не переносится:
для нового образа нужна новая проверка и, если всё ещё необходимо, новое
обоснование с новой точной привязкой.

Runtime evidence строится именно из опубликованного `${IMAGE}@sha256:…`:
workflow выполняет `docker image inspect`, затем `docker create` и
`docker export`, но никогда `docker run`. Скрипт проверяет digest, `amd64`,
non-root user, точный Uvicorn CMD, список установленных Debian-пакетов,
отсутствие релевантных Perl-модулей и статически разбирает Python-исходники в
`/app/app`. Для native call path он без запуска разбирает undefined dynamic
symbols каждого ELF64-файла и сканирует exact rootfs: импорты устаревших
DNS-print функций, формат `%mc` с явной шириной больше 1024 и ссылки на
`ungetwc`/`libstdc++` в runtime-поверхности `/app` + `/usr/local`. В
`candidateClaims` перечислена 21 CVE и поддерживающие проверки.
`checksPassed: true` означает только, что автоматические факты сошлись: он не
создаёт VEX и не заменяет чтение advisory и review.

## Жизненный цикл исключений

- VEX хранится как `security/vex/<64 hex digest>.cdx.json` и применим только к
  указанным CVE/package/version/purl/digest.
- Для VEX, опирающегося на runtime path, evidence должно ссылаться на успешный
  `*-evidence.json` того же digest и отдельно объяснять, почему конкретные
  условия advisory не достигаются. Одного `checksPassed` недостаточно.
- Waiver хранится в `security/waivers.json`, действует не более 30 дней и после
  `expiresAt` перестаёт подавлять автоматически.
- Продление waiver — новая запись и новый review, а не изменение старой даты.
- Когда digest больше не обслуживает traffic/tagged revision, его активные
  policy-записи удаляются обычным PR. Git-история сохраняет решение; отдельный
  архив удалённых image/SBOM проект намеренно не ведёт.
- Отсутствие успешного scheduled run более восьми дней — повод проверить GitHub
  schedule, WIF/GCP и выполнить ручной запуск.

## Что сознательно не входит

- **Next.js/Vercel artifact SBOM.** Этот контур покрывает только контейнер
  FastAPI. Зависимости Next.js контролируются lockfile, Dependabot, Dependency
  Review и SCA; опись Vercel build output здесь не создаётся.
- **Dependency-Track.** Для одного контейнерного сервиса отдельная БД,
  dashboard и её эксплуатация не окупаются. Триггер пересмотра — несколько
  сервисов/команд, необходимость долгой истории, централизованных SLA и API.
- **Provenance, подпись и attestation.** SBOM отвечает «что внутри», но не
  доказывает, какой pipeline это собрал. Это отдельная будущая задача.
- **Автоматический запрет deploy.** Текущий image-scan — operational gate.
  Триггер пересмотра — выход приложения за текущий ограниченный круг,
  появление отдельной команды эксплуатации или требование release SLA.

На production digest
`sha256:0827603eeb37e4f31ef2486eb0de757850e2dea548a47aa7497e06b0b1752fe3`
run `33299518793` подтвердил runtime evidence: 22/22 checks и 21/21 candidate
claims, включая 754 ELF exact rootfs; контейнер не запускался. После чтения
официальных advisory VEX из review-PR №38 и №40 покрывает 27 exact package
match по 21 CVE. Финальный production run `33308851706` подтвердил ту же
политику: до неё Critical=7 и High=20, подавлено VEX=27 и waiver=0, после неё
Critical=0 и High=0, `Gate: PASS`; истёкших waiver match нет. Waiver
по-прежнему пуст.
