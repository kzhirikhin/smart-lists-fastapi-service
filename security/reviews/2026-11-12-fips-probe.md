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

Candidate нового deploy ещё не проверен этой exact-пробой. Сканер продолжает
блокировать и serving, и новый deploy; исключение или ослабление gate в этой
задаче не применялось. Следующий шаг перед rollout — отдельное решение о
точном non-affected обосновании/механизме pre-deploy либо официальный patch.
Политика не должна превращаться в blanket-исключение Python/FIPS или High.

Прямой GCP login/ADC, ключи и IAM-изменения не использовались. Job работает
на краткоживущей identity существующего workflow; platform credentials не
передаются исполняемому image. Настоящий AI-ответ в production после нового
исправления не проверялся: rollout не состоялся.
