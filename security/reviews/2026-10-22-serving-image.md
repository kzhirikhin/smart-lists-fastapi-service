# Разбор оставшихся advisory High — 2026-10-22

Объект: serving manifest
`sha256:b36483f57518b5b9889b97f6323186763ffe24cb869689b6e9ee9100096c4c9b`,
source `24dbe7b6924da0bfe603537bd209b7bde9dfb328`.
[Scan 39732626472](https://github.com/kzhirikhin/smart-lists-fastapi-service/actions/runs/39732626472)
завершился успешно: Critical=0, 55 advisory High, VEX=0, waiver=0.
55 — число совпадений CVE с пакетами, уникальных CVE — 14.
SHA-256 скачанного artifact `12404959654` проверен:
`a7d71c2c1b49de2cf090d4f7f998d34ae950488d21bf1db380e00be16586ee01`.

Это review и дополнительные проверки evidence, не новое VEX-решение.
Три новых candidate claims подтверждены локально на exact rootfs: PASS,
29/29 checks, 30/30 candidate claims, 752 ELF. Старый artifact их не
выполнял. CVE-2026-102010 разобрана, но остаётся без
доказанного `not_affected`: поиск маркеров не исключает статический шаблон.
До отдельного решения все 55 совпадений остаются advisory по A100.

## Сверка всего текущего набора

| CVE | Совпадений | Предыдущий разбор / текущий статус |
| --- | ---: | --- |
| CVE-2025-69720 | 4 | Старый VEX: CLI infocmp; соответствующие candidate checks текущего artifact PASS |
| CVE-2026-5435 | 2 | Старый VEX: устаревшие DNS-print функции glibc; checks PASS |
| CVE-2026-54369 | 1 | Старый VEX: привилегированный ACL-путь; checks PASS |
| CVE-2026-54370 | 1 | Старый VEX: привилегированные ACL-утилиты; checks PASS |
| CVE-2026-76642 | 9 | Review 09-07: mount hooks; checks PASS |
| CVE-2026-78408 | 9 | Review 09-07: nsenter; checks PASS |
| CVE-2026-78409 | 9 | Review 09-07: fstab subdir; checks PASS |
| CVE-2026-78410 | 9 | Review 09-07: fstab bind-source; checks PASS |
| CVE-2026-85091 | 1 | Review 09-07: gzwrite/gzprintf; checks PASS |
| CVE-2026-9538 | 1 | Старый VEX: отсутствующий Archive::Tar; checks PASS |
| CVE-2026-95619 | 3 | Новый разбор ниже; candidate checks exact rootfs PASS |
| CVE-2026-19499 | 2 | Новый разбор ниже; candidate checks exact rootfs PASS |
| CVE-2026-82560 | 1 | Новый разбор ниже; candidate checks exact rootfs PASS |
| CVE-2026-102010 | 3 | Новый разбор ниже; статический PBDS не исключён |
| **Итого** | **55** | **14 уникальных CVE** |

Старые statements хранятся в `security/vex/`, включая review PR #63.
Их exact purl/version/digest не переносятся. PASS candidate checks — только
проверенные факты, не автоматическое решение о достижимости или исправлении.

## Четыре новых разбора

### CVE-2026-95619 — GCC / aligned operator new

Три совпадения: `gcc-14-base`, `libgcc-s1`, `libstdc++6` версии `14.2.0-19`.
[Debian tracker](https://security-tracker.debian.org/tracker/CVE-2026-95619)
помечает trixie vulnerable/no-dsa. Наличие исправления в unstable не означает
наличия обновления для нашего trixie.
[Upstream fix](https://github.com/gcc-mirror/gcc/commit/200183d4ab5d57575f3dfebc6af3baf649910b9e)
уточняет условие: переполнение при округлении размера в определённых
реализациях aligned new; ветка posix_memalign такого округления не делает.
Последнее не принимается за доказательство конфигурации Debian-бинарника.

Проверяем другой, более узкий факт: runtime `/app` + `/usr/local` не должен
содержать ссылок на libstdc++, GLIBCXX или CXXABI. Старый evidence уже проверял
отсутствие `libstdc++.so.6` вместе с ungetwc; новый отдельный check расширяет
маркеры и не смешивает две причины. В сочетании с точным Uvicorn CMD,
отсутствием запуска процессов и прямой native-загрузки это поддерживает
кандидата `code_not_reachable`. Прогон новых checks на exact rootfs дал
PASS; установленная системная библиотека не объявляется исправленной.

### CVE-2026-19499 — glibc / strfmon

Два совпадения: `libc6` и `libc-bin` версии `2.41-12+deb13u4`.
[Debian tracker](https://security-tracker.debian.org/tracker/CVE-2026-19499),
[GLIBC-SA-2026-0017](https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=advisories/GLIBC-SA-2026-0017;hb=HEAD).
Нужен вызов strfmon/strfmon_l с правым выравниванием в недостаточный буфер;
поле ширины может быть константой, поэтому отсутствия формата во входном API
недостаточно для исключения.

Новый check ищет `strfmon` во всех файлах `/app` + `/usr/local`, включая
Python stdlib, native-модули и данные для dlsym. Он захватывает также
strfmon_l и внутренние имена с этим фрагментом. Вместе с запретом процессов
и прямой native-загрузки это кандидат `code_not_reachable`, а не утверждение,
что glibc без дефекта. Проверка exact rootfs дала PASS: маркеров нет.
Старый artifact такой поиск не выполнял.

### CVE-2026-82560 — Perl / Pod::Text

Одно совпадение: `perl-base` версии `5.40.1-6+deb13u1`.
[Debian tracker](https://security-tracker.debian.org/tracker/CVE-2026-82560),
[исправление Pod::Text](https://github.com/rra/podlators/commit/70510174f69eb54aa6d617bde4e1402cd9b7c61f).
Вложенные POD-отступы могут свести доступную ширину к нулю; форматирование
зацикливается с ростом памяти. Это конкретный Perl-модуль, не любой текст
и не JSON/Python re.

Проверки отсутствия полных Perl-пакетов уже прошли, но наличие одного
perl-base не доказывает отсутствия вручную скопированного модуля. Новый check
ищет Pod/Text.pm, Pod/Text.pmc и подклассы Pod/Text/ по всему rootfs.
В exact rootfs этих путей нет, новый check PASS: это поддерживает кандидата
`code_not_present`. Старые проверки Archive::Tar не подменяют Pod::Text.

### CVE-2026-102010 — GCC / PBDS binary heap erase_if

Три совпадения с теми же GCC-пакетами `14.2.0-19`.
[Debian tracker](https://security-tracker.debian.org/tracker/CVE-2026-102010),
[upstream fix](https://gcc.gnu.org/git/?p=gcc.git;a=commit;h=aaa8351f4d2e636f9680a1f0a8ebc2f0a60611e6).
После перераспределения памяти binary_heap erase_if не заменяет внутренний
указатель. Существенно, что исправлен файл
`include/ext/pb_ds/detail/binary_heap_/erase_fn_imps.hpp`: шаблон может быть
встроен в вызывающий ELF. Отсутствие DT_NEEDED на libstdc++ не исключает CVE.
Новый автоматически разрешающий candidate claim поэтому не добавляется.

Дополнительно прочитаны sdist точных версий шести native-зависимостей из
requirements.txt. Архивы получены через PyPI JSON API; их SHA-256 совпал с
метаданными PyPI. Ничего из архивов не устанавливалось и не исполнялось.
Во всех файлах искались `__gnu_pbds`, `ext/pb_ds`, `binary_heap_` и
`priority_queue.hpp`; совпадений нет. C/Cython/Rust-файлы есть, `.cpp/.cc/.cxx/.hpp`
в этих архивах не найдены.

| sdist | SHA-256 |
| --- | --- |
| cffi 2.1.1 | `dd31f52ea1086513bb9df30f8fcee9b8918323ae067a3d5b78bc826a000712be` |
| charset-normalizer 3.5.1 | `6117b84ea48435e5356dc737f5121485c30920ba43375fa7b434fd753df0eac3` |
| cryptography 50.0.1 | `5dd9bda1c12b4162f6ff568eeb5e0ff956c28d14406e875cfe8a63a2d414ff20` |
| pydantic-core 2.46.5 | `10416c15b8839ecc4ef4d0885da76da6fd0f67333a0eb8aff6d93c4b8f2910fc` |
| websockets 16.1.1 | `db234eda965dcce15df96bb9709f587cd87d4d52aaf0e80e2f34ec04c7670c57` |
| wrapt 2.5.0 | `c48cdb6c904dca76d9915a579e4a5fab6b0c25f650c1019ce78a78effaf7a345` |

Эта выборка уменьшает подозрение на обычный runtime-путь, но не является
полным доказательством: sdist не доказывает соответствие опубликованному
wheel, Rust crates и встроенные сторонние библиотеки здесь не разобраны,
CPython/системные ELF не восстановлены из полного набора build inputs.
Практически достижимый путь не установлен; `not_affected` не выдан.
Сохранение advisory — существующая политика A100, не новый waiver.
Следующий шаг для исключения: доказать отсутствие шаблона в native build
inputs exact image либо обновить GCC-пакеты после исправления в trixie.

В exact `/app` + `/usr/local` перечисленные четыре PBDS-маркера также не
найдены. Перечень всех native ELF из site-packages содержит семь файлов:
`_cffi_backend`, `charset_normalizer/cd`, `charset_normalizer/md`,
`cryptography/hazmat/bindings/_rust`, `pydantic_core/_pydantic_core`,
`websockets/speedups`, `wrapt/_wrappers`. Они относятся ровно к шести
исследованным дистрибутивам. Это проверяет состав выбранной поверхности,
но не восстанавливает отсутствующие после оптимизации символы и не снимает
описанное ограничение source/wheel.

## Границы и проверка

Новые маркерные checks покрывают только `/app` и `/usr/local`; системные
библиотеки вне них не получают полного call-graph анализа. Статически
встроенный код, намеренная обфускация, вычисляемые имена dlsym и RCE не
исключаются. Отсутствие subprocess/native imports проверяется в приложении,
не во всех исходниках зависимостей. Runtime configuration overrides,
добавленные тома и актуальный трафик Cloud Run
были сверены read-only через Cloud Run API 2026-10-22: ревизия
`insights-api-00068-mdn` получает 100% трафика, указывает на указанный digest,
command/args overrides и volume mounts/volumes отсутствуют. Это ручная
проверка на дату, не гарантия последующего состояния платформы.

Негативные тесты добавляют strfmon/libstdc++ маркеры в runtime-зависимость,
Pod::Text/pmc/подкласс вне стандартного пути и проверяют провал связанного
claim. Отдельно закреплено отсутствие автоматического PBDS-исключения.
Все 297 тестов прошли в Python 3.14/Linux-контейнере без сети и credentials;
GitHub CI PR #89, Gitleaks и CodeQL также прошли. Exact production image
скачан по digest, инспектирован и экспортирован через create/export без
исполнения контейнера. Новая локальная проверка дала PASS 29/29 и 30/30;
итоговый JSON сохранён как `exact-evidence.json` в локальном каталоге review.
PR #89 слит commit `511a6fe5e048b7998783e86719dd983ba85bdb1c`.
[Main-scan 39783031067](https://github.com/kzhirikhin/smart-lists-fastapi-service/actions/runs/39783031067)
на том же serving digest подтвердил provenance/evidence/policy PASS:
29 checks, 30 candidate claims, 752 ELF, Critical=0, 55 advisory High,
VEX/waiver=0. JSON evidence/policy/raw и Markdown summary artifact `12427378925`
прочитаны; набор 14 CVE и counts по пакетам совпали с исходным scan.
В том числе пройдены три новых candidate claims. Artifact SHA-256 по GitHub metadata:
`d04c0305ff5815148b09c3d485ce347bc16aff7309f50ce372a7c2c7c1e6abf8`.
VEX и waiver не изменены; PASS не превращает все 14 CVE в `not_affected`.

Impact-check: затронут TB11/A66 (доказательства scanner), активы — rootfs и
результат CVE-review; новые внешние runtime-сервисы, зависимости, права и
payload отсутствуют. Политика A65/A100 и VEX/waiver не меняются. Поломка
маркерного факта должна давать FAIL, но полнота reachability не заявляется.
