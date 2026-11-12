# OpenTelemetry candidate: exact non-affected review CVE-2026-119170

Проверено 2026-11-12 по явно разрешённой владельцем диагностике и поручению
подготовить точечный допуск с rollout. Проверку кода/evidence выполнил Codex;
владелец/ответственный за принятие — @kzhirikhin. Это не blanket-исключение Python.

## Подписанный артефакт

- Исходный deploy: 43181145499, production/push/main, source
  `5b6eb992beaa0d2c404bd5b687b900f29a4974e5` (OpenTelemetry 1.45.1).
- OCI parent: `sha256:73784498e77809ea195a4f68753d93064f14fe9a3fbb6cb2933a9994fc087bba`.
- Единственный linux/amd64 child:
  `sha256:7faf8be3bd0a07dc0123d1bbfd58586d7fe909b3ebaca8f6f09d1a689c581d7c`.
- Не меняется на новый build/tag; VEX относится только к этому child.

[Candidate job 43185846747](https://github.com/kzhirikhin/smart-lists-fastapi-service/actions/runs/43185846747)
прошла. Artifact `fips-probe-43185846747` содержит fips-candidate.json и
fips-candidate-verification.json. До Docker execution повторно проверены
Sigstore подпись и subject, signer/source SHA, refs/heads/main, production/push,
repository ID 1199475908 и github-hosted runner через существующий DER verifier.
Parent index криптографически связывает exact child; исходник подписи — deploy.yml.

## Проверенные условия

[PSF advisory](https://mail.python.org/archives/list/security-announce@python.org/message/PXVTTOBPUMFJSSUXN6XCS7FC5DZOSZXK/)
описывает регрессию FIPS-enforcement hashlib только для Python 3.14.10
при использовании OpenSSL FIPS. Указанный Grype fixed-in 3.14.11 ещё не
опубликован (официальный tag/Docker manifest проверены 2026-11-12).

Exact child в ограниченной копии показал:

- Python 3.14.10; OpenTelemetry API 1.45.1; OpenSSL 3.5.7.
- `_hashlib.get_fips_mode() == 0`.
- fips.so в /usr/lib и /usr/local/lib: 0.
- У serving revisions и текущего service template отсутствуют выбранные
  FIPS/OpenSSL/LD/PYTHONPATH/PYTHONHOME env, mounts/volumes и command/args overrides.
- Service baseline остаётся insights-api-00070-q8b / child 534fcd9b…d802e870.

В контейнер не передавались host env, credentials или mounts; сеть выключена,
FS read-only, UID 10001, cap-drop/no-new-privileges, memory/pid/CPU/time limits.
Текущие app entrypoints не включают FIPS. Это cold image probe, не чтение памяти
работающего процесса; отсутствие fips.so само по себе не исключало бы
переименованный или встроенный provider. Вывод опирается также на фактический
режим, frozen image и выбранные runtime guards.

## Решение и удержание границ

Для ровно CVE-2026-119170 / python 3.14.10 / pkg:generic/python@3.14.10
и указанного child подготовлен CycloneDX not_affected с justification
requires_configuration: необходимый FIPS-режим в проверенном deployment
не включён. Это не принятие реально включённого FIPS и не waiver.

Manual promotion повторяет подпись, linked child, пакет/FIPS probe, отсутствие
selected runtime overrides, SBOM attachment и fresh full scan. Разрешён один
exact VEX, ноль waiver и иных блокирующих High/Critical; review window <=7 дней,
record/VEX metadata совпадают, baseline не может быть произвольным новым image.
Обычный build/deploy gate не меняется. Перед повторным применением VEX в
recurring scan metadata-only guard проверяет выбранные runtime условия.
Любой drift, другой image/package/CVE или technical error требует нового review.

Guard не является общей политикой всех возможных provider activation paths.
Остаются доверие main/runner/Docker и TOCTOU относительно внешних control-plane
изменений вне GitHub concurrency. При включении FIPS, runtime overrides,
новом digest, новых сведениях advisory или официальном patch это решение
пересматривается. Следующий image не наследует VEX автоматически.

VEX и promotion record приняты отдельным PR #107 после проверки evidence.
Результат выполнения и границы записаны ниже.

## Успешный promotion и независимая проверка (2026-11-12)

Отдельный exact VEX/record принят PR #107/main@d9a79e3; механизм — PR #106,
YAML-команда install исправлена PR #108. Record promotion действует до
2026-11-19T09:01:20Z; это окно выполнения promotion, не blanket срок VEX.

[Manual promotion 43188890883](https://github.com/kzhirikhin/smart-lists-fastapi-service/actions/runs/43188890883)
успешно повторил tests, подпись/source/claims, linked child, FIPS/пакеты,
SBOM attachment, fresh full Grype и selected runtime guards. Cloud Run
обслуживает insights-api-00071-2kt с exact child
`sha256:7faf8be3bd0a07dc0123d1bbfd58586d7fe909b3ebaca8f6f09d1a689c581d7c`.
Parent остался `sha256:73784498e77809ea195a4f68753d93064f14fe9a3fbb6cb2933a9994fc087bba`,
source — `5b6eb992beaa0d2c404bd5b687b900f29a4974e5`.

[Независимый serving scan 43189371657](https://github.com/kzhirikhin/smart-lists-fastapi-service/actions/runs/43189371657)
подтвердил provenance/evidence, exact FIPS runtime guard и policy PASS:
raw Critical=0/High=60, VEX=1, waiver=0, блокирующих Critical=0/High=0,
advisory High=59. FIPS-проба нового serving child: Python 3.14.10,
OpenSSL 3.5.7, FIPS=0/fips.so=0; selected runtime overrides отсутствуют.

Пакет OpenTelemetry API 1.45.1 подтверждён candidate-пробой того же immutable
child. Неприменимость Python FIPS CVE условна и относится только к exact
image/package/configuration; новый image не наследует VEX. Включение FIPS,
selected runtime drift, новые сведения advisory или официальный patch требуют
пересмотра. Обычный push-deploy gate не ослаблялся, другие CVE не исключались.
420 pytest без сети/pip check прошли; в web — lint/typecheck, 843 unit и
589 static-security проверок. Реальный AI-ответ через production UI после
этой выкладки не проверялся; это остаётся отдельной ручной проверкой владельца.
