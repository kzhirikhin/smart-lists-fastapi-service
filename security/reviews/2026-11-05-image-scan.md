# Разбор блокирующего image-scan — 2026-11-05

[Запуск 41816747488 от 2026-11-04](https://github.com/kzhirikhin/smart-lists-fastapi-service/actions/runs/41816747488)
проверил serving manifest
`sha256:b36483f57518b5b9889b97f6323186763ffe24cb869689b6e9ee9100096c4c9b`.
Provenance и evidence прошли; gate BLOCKED: Critical=1, исправимых High=4,
неисправимых advisory High=60, VEX=0, waiver=0. Технической ошибки Grype нет.
Это единственная job `scan`; сообщение «All jobs have failed» не означает
остановку Cloud Run. 28 октября тот же workflow SHA был зелёным; новые
результаты отражают обновляемую базу уязвимостей, а не изменение приложения.

## Находки и решение

| Находка | Состав образа | Решение |
| --- | --- | --- |
| CVE-2026-115557, Critical | Python 3.14.9 | Python 3.14.10 в builder/runtime и CI |
| GHSA-fm9c-5rcf-2q5p / CVE-2026-119194 | pyasn1 0.6.4, контейнеры без ASN.1 schema | pyasn1 0.6.5 |
| GHSA-9m75-vc3g-4x39 / CVE-2026-119195 | pyasn1 0.6.4, constructed strings / ANY | pyasn1 0.6.5 |
| GHSA-2qm8-x737-gmw5 / CVE-2026-119196 | pyasn1 0.6.4, constructed BIT STRING | pyasn1 0.6.5 |
| GHSA-mm57-4v3p-rchx / CVE-2026-119197 | pyasn1 0.6.4, binary REAL | pyasn1 0.6.5 |

[CPython release](https://www.python.org/downloads/release/python-31410/)
и [upstream issue](https://github.com/python/cpython/issues/160040) описывают
отказ доверять скомпрометированным eMudhra intermediate CA keys внутри ssl.
Это дополнительная защита к удалению emSign root из certifi (A109), а не
свидетельство компрометации сервиса или исправление уже выполненной атаки.
Затронуты TLS получения Google signing keys (TB4) и исходящий Vertex TLS (TB5).

Четыре [pyasn1 advisory](https://github.com/pyasn1/pyasn1/security/advisories)
описывают квадратичный расход CPU при разборе специально подготовленного ASN.1.
Цепочка — google-auth → pyasn1-modules → pyasn1. Сервис принимает JSON и Google
JWT; произвольный ASN.1 payload не передаёт декодеру напрямую. В проверенном
окружении RSA-проверка использует cryptography для PEM/X.509. Полная
недостижимость всех SDK/ADC/fallback-путей не доказана; VEX не выдаётся.
Точечный доступный patch предпочтительнее исключения.

PyPI wheel 0.6.5 опубликован 2026-10-27; SHA-256
`4017b0fce125096b8573b39c989fdb1a4b19cf761e683398184550fea0e66587`.
Оба lock пересобраны штатным pip-compile 7.5.3 / pip 25.3 в Linux Python 3.14.10.
Единственная сменившаяся версия lock — pyasn1. Python release от 25 октября
и wheel старше семи дней; исключения из cooldown не нужны.

## Проверка и остаток

- Хешированная установка только wheel и pip check в чистом контейнере: PASS.
- `pytest tests/ -v` с отключённой сетью: 299 passed, два прежних deprecation warnings.
- Production Dockerfile: build PASS; Python 3.14.10, pyasn1 0.6.5, UID 10001,
  pip отсутствует. Без сети: health 200, docs 404, malformed insights без
  токена 403 до разбора body; строгие TLS contexts и отсутствие emSign root
  в requests/httpx сохранены.
- Новые тесты проверяют минимальные установленные версии и точное равенство
  patch pins builder/runtime/workflows. Они не воспроизводят MITM и не
  доказывают линейность каждого ASN.1 decoder.
- Grype 0.117.0 (официальный SHA-256 проверен), база от 2026-11-04 06:20:59Z,
  локальный OCI index `sha256:654f9c446cd0d6adf4e0ceed17e49c8bd6299f43e22b7a7171743c028c669b5a`:
  Critical=0, блокирующих High=0, advisory High=60, VEX/waiver=0, Gate PASS.
  Raw JSON оценён неизменённым scripts/evaluate_image_scan.py. Это локальный
  docker-archive scan; production provenance/serving-child он не подтверждает.
- Отрицательная проба настоящим wheel pyasn1 0.6.4 в отдельном target приводит
  к ожидаемому падению нового теста. Python guard отвергает синтетический
  sys.version_info 3.14.9; старый Python runtime этой пробой не запускался.
- Production не менялся; старый BLOCKED не закрыт локальной сборкой. После deploy нужен read-only
  serving scan с provenance/evidence и свежей базой, затем ручной AI smoke.

IAM, OIDC/WIF, API-контракт, payload/prompt, лимиты, VEX/waivers и gate не меняются.
Новых сервисов, секретов и границ доверия нет. Остаток A100 (неисправимые High
не блокируют) сохраняется; прежние exact VEX не переносятся на новый digest.
