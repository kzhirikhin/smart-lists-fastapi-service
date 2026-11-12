# Проверка применимости CVE-2026-119170 (2026-11-12)

## Состояние выпуска

OpenTelemetry API 1.45.1 опубликован в исходниках FastAPI PR #102,
main@5b6eb992beaa0d2c404bd5b687b900f29a4974e5. CI, CodeQL и dependency review
прошли. Deploy [43181145499](https://github.com/kzhirikhin/smart-lists-fastapi-service/actions/runs/43181145499)
остановился на pre-deploy Grype до изменения Cloud Run. Candidate OCI parent:
`sha256:73784498e77809ea195a4f68753d93064f14fe9a3fbb6cb2933a9994fc087bba`.
Причина: High CVE-2026-119170, Python 3.14.10, fixed-in 3.14.11.
На дату проверки официальный tag v3.14.11 и Docker manifest python:3.14.11-slim
отсутствовали. Это не основание заменить runtime на prerelease или отключить gate.

[PSF advisory](https://mail.python.org/archives/list/security-announce@python.org/message/PXVTTOBPUMFJSSUXN6XCS7FC5DZOSZXK/)
ограничивает уязвимость Python 3.14.10 и OpenSSL FIPS: регрессия принудительного
выбора допустимых алгоритмов hashlib. Наличие версии в scanner match само
по себе не доказывает включённый FIPS.

## Проверка serving-образа

Read-only serving scan
[43181865048](https://github.com/kzhirikhin/smart-lists-fastapi-service/actions/runs/43181865048)
подтвердил provenance/evidence прежнего production child; policy FAIL:
Critical=0, блокирующая High=1 (эта CVE), advisory High=59, VEX/waiver=0.
Это отличается от успешного scan 11 ноября из-за обновления vulnerability DB.

Владелец отдельно разрешил ручную FIPS-job в image-scan.yml. Она опубликована
в PR #103, main@d1fb01c. CI/CodeQL/dependency review и 353 локальных pytest
прошли. Штатный offline evidence по-прежнему не запускает image. Новая
opt-in job использует прежнюю main-only read-only scanner identity;
Cloud Run, IAM, трафик, VEX и scan policy не меняются.

Результат fips_probe job
[43183151100](https://github.com/kzhirikhin/smart-lists-fastapi-service/actions/runs/43183151100),
artifact `fips-probe-43183151100/fips-probe.json`:

- Ревизия: `insights-api-00070-q8b`.
- Exact image child: `sha256:534fcd9b6d813f37a9307e1706302d79d1215abbb6a449a59c74da27d802e870`.
- Cold Python: 3.14.10, OpenSSL 3.5.7, fipsMode=0.
- Найденных fips.so в /usr/lib и /usr/local/lib: 0.
- Релевантные FIPS/OpenSSL/LD/PYTHONPATH/PYTHONHOME runtime env: отсутствуют.
- Volumes и command/args overrides: отсутствуют.
- policyChanged=false.

Контейнер запущен по exact digest с --network=none, без передачи host env,
credentials или mounts; rootfs read-only, UID 10001, cap-drop/no-new-privileges,
лимиты CPU/memory/pids и timeout. Artifact содержит только version/FIPS и
выбранные имена env/булевы признаки; значения env не публикуются.

## Вывод и границы

Условие применимости этой CVE не обнаружено в проверенной изолированной копии
serving-образа и выбранных runtime-настройках ревизии. Это датированное
наблюдение, не проверка памяти уже работающего процесса, не доказательство
всех поздних загрузок providers и не гарантия следующего digest. Переименованный
или встроенный provider не исключается одним поиском fips.so; вывод опирается
также на фактический fipsMode=0 и отсутствие выбранных overrides.

Эта первоначальная serving-проба не покрывала candidate нового deploy.
Он позднее проверен отдельно job 43185846747 (signed source/parent/child,
OpenTelemetry 1.45.1, FIPS=0/fips.so=0, selected serving/template overrides нет).
После отдельного review PR #107 применён только exact VEX для candidate child;
другие CVE/digests/waiver этим не допускаются. Результат promotion — ниже.

Прямой GCP login/ADC, ключи и IAM-изменения не использовались. Job работает
на краткоживущей identity существующего workflow; platform credentials не
передаются исполняемому image. Настоящий AI-ответ через UI после rollout не проверялся.

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
