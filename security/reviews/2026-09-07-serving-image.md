# Проверка рабочего образа 2026-09-07

Объект: `sha256:16b779ddb9918880d95ae264f6be3923037b44c4edd2365fa40d60e64bfa79ea`,
Cloud Run revision `insights-api-00057-rlj`, source `a0d049c`.
[Scan 34118042409](https://github.com/kzhirikhin/smart-lists-fastapi-service/actions/runs/34118042409)
подтвердил provenance и исходный runtime evidence, но policy была BLOCKED:
7 Critical + 58 High package matches, 27 уникальных CVE, VEX=0, waiver=0.

## Метод и факты

Все 27 записей повторно прочитаны в Debian Security Tracker 2026-09-07.
Опубликованный образ скачан по полному digest и разобран через
`docker image inspect`, `docker create`, `docker export`; контейнер не запускался.
Расширенный `verify_image_evidence.py` получил PASS: 26 checks, 27 candidate
claims, 754 ELF. Проверка Cloud Run API подтвердила тот же digest, отсутствие
command/args overrides и подключённых томов. Это ручная сверка внешней
конфигурации на указанную дату; локальный rootfs сам её не доказывает.

Прежние 21 CVE перепроверены на новом rootfs: отсутствующие Perl-модули,
amd64 вместо требуемого 32-bit Perl, отсутствие запуска дочерних процессов и
SQLite в приложении, отсутствие native-loading и прежние три glibc-предусловия.
Ни одно старое digest-исключение автоматически не переносится.

| Новая CVE | Требуемый путь и проверенный факт |
| --- | --- |
| [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642) | Привилегированные post-mount hooks после отказа helper. Root-owned `fstab` не содержит записей, приложение не запускает mount и runtime не ссылается на libmount. |
| [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409) | Разрешённый fstab `X-mount.subdir` и привилегированный mount. В exact image нет fstab-записей или runtime-вызова libmount/mount. |
| [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410) | Разрешённый fstab bind-source и подмена пути. Тот же пустой root-owned fstab и отсутствие mount-потока. |
| [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408) | Привилегированный `nsenter --join-cgroup` с последующим exec. CMD — Uvicorn под appuser; приложение не создаёт процессы и не содержит nsenter-команд. |
| [CVE-2026-85091](https://security-tracker.debian.org/tracker/CVE-2026-85091) | Non-blocking gzwrite после stall, затем gzprintf/gzvprintf. Во всей `/app` + `/usr/local` нет маркеров этих API; приложение не запускает CLI и не загружает native libraries. Обычный inflate HTTP-ответов — другой путь. Не опираемся только на спорную границу версии: Debian пока помечает trixie vulnerable. |
| [CVE-2026-86145](https://security-tracker.debian.org/tracker/CVE-2026-86145) | Recursive DFA matching в PCRE2 с атакуемым regex. В runtime-поверхности нет ссылок на libpcre2 или pcre2_dfa_match; Python re не является PCRE2. |

Debian trixie пока не предоставляет фикс для этих шести находок по tracker:
util-linux и PCRE2 помечены no-dsa, zlib — unfixed. Подмена системных пакетов
на Debian unstable не требуется для доказанного отсутствия exploit path.

## Ограничения и проверка

Решение — точный CycloneDX `not_affected`, не waiver и не заявление об
исправлении установленных библиотек. Оно относится только к указанным
CVE/package/version/purl/digest и текущей конфигурации запуска. RCE, добавление
плагинов, dynamic native-loading, новых процессов, mount-конфигурации или смена
образа требуют нового разбора. Статический поиск не доказывает отсутствие
намеренно обфусцированного кода; происхождение и review зависимостей остаются
отдельной границей доверия.

Негативные тесты проверяют fstab с записью, чужим владельцем, writable mode,
symlink, отсутствием и неверной кодировкой; появление native API в зависимости
и команд mount/nsenter в приложении делает соответствующие claims ложными.
Новый evidence обязан пройти в штатном operational workflow после merge.
До его успешного завершения состояние production gate остаётся BLOCKED.
