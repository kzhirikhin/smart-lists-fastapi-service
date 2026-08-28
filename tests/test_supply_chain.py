"""Статические контракты цепочки поставок.

Проверки читают файлы репозитория и падают на нарушении. Смысл именно в форме:
все три утверждения ниже сегодня истинны, и защищать надо не их появление, а то,
что они не станут ложными молча. Разница между «сегодня верно» и «не может стать
неверным» — это наличие проверки.

Аналог в основном репозитории — набор `security-static`. Здесь отдельного gate
нет, поэтому контракты живут в обычном прогоне pytest, который уже является
required check.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"

# Значение `uses:` вместе с остатком строки: комментарий версии проверяется той
# же проверкой, что и сам пин.
USES = re.compile(r"^\s*(?:-\s*)?uses:\s*(\S+)(.*)$", re.MULTILINE)

# Строка `name==version` в начале записи pip-compile.
PINNED = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s\\]+)", re.MULTILINE)


def _workflows() -> list[tuple[str, str]]:
    return sorted(
        (path.name, path.read_text(encoding="utf-8"))
        for path in WORKFLOWS_DIR.iterdir()
        if path.suffix in {".yml", ".yaml"}
    )


def _action_refs() -> list[tuple[str, str, str]]:
    refs: list[tuple[str, str, str]] = []
    for name, body in _workflows():
        for match in USES.finditer(body):
            refs.append((name, match.group(1), match.group(2)))
    return refs


def _pins(filename: str) -> dict[str, str]:
    body = (REPO_ROOT / filename).read_text(encoding="utf-8")
    # Комментарии отбрасываются: `# via fastapi` под каждой записью и заголовок
    # pip-compile не должны попадать в разбор.
    payload = "\n".join(
        line for line in body.splitlines() if not line.lstrip().startswith("#")
    )
    return {
        name.lower().replace("_", "-"): version
        for name, version in PINNED.findall(payload)
    }


class TestActionPins:
    """Actions закреплены по SHA.

    Тег в реестре — это имя, которое владелец может переставить на другое
    содержимое в любой момент: `@v7` завтра означает не то, что сегодня, и в
    диффе не будет ни строки. Скомпрометированный action исполняется с правами
    workflow, а в `deploy.yml` — рядом с OIDC-токеном на Cloud Run.
    """

    def test_workflows_are_visible(self) -> None:
        # Проверки ниже проходят и на пустом списке, поэтому сначала требуем,
        # чтобы разбор действительно что-то нашёл.
        names = [name for name, _ in _workflows()]
        assert "ci.yml" in names
        assert "deploy.yml" in names
        assert len(_action_refs()) >= 5

    @pytest.mark.parametrize(("workflow", "ref", "rest"), _action_refs())
    def test_pinned_by_full_sha(self, workflow: str, ref: str, rest: str) -> None:
        if ref.startswith("./") or ref.startswith("../"):
            # Локальное действие приезжает тем же checkout, что и код;
            # подменить его переносом тега нельзя.
            return
        # Ровно 40 hex после `@`: `@v7`, `@main` и укороченный SHA не проходят.
        assert re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", ref), f"{workflow}: {ref}"

    @pytest.mark.parametrize(("workflow", "ref", "rest"), _action_refs())
    def test_version_comment_present(self, workflow: str, ref: str, rest: str) -> None:
        if ref.startswith("./") or ref.startswith("../"):
            return
        # Без комментария человек не может прочитать закреплённую версию, не
        # сходив в реестр. Dependabot двигает пин вместе с комментарием.
        assert re.search(r"#\s*v?\d", rest), f"{workflow}: {ref}"


class TestRequirementsDrift:
    """`requirements.txt` не расходится с `requirements.in`.

    Полные наборы разворачивает pip-compile, но pip читает только `.txt`.
    Поэтому ручная правка `.txt` — например, чтобы поднять одну версию, не
    поднимая контейнер, — делает `.in` документацией, которая больше не
    описывает реальность, и делает это молча. У npm ту же роль бесплатно
    выполняет `npm ci`, отказываясь работать при расхождении lock и manifest;
    у pip аналога нет, потому что `.in` — не манифест, о котором pip знает.

    Транзитивные версии проверкой не покрыты: для них нужен настоящий прогон
    pip-compile в контейнере. Здесь закреплено то, что расходится на практике, —
    прямые зависимости.
    """

    def test_direct_pins_match_compiled_output(self) -> None:
        for source, compiled in (
            ("requirements.in", "requirements.txt"),
            ("requirements-dev.in", "requirements-dev.txt"),
        ):
            declared = _pins(source)
            resolved = _pins(compiled)
            assert declared, f"{source}: прямые зависимости не разобраны"

            for name, version in declared.items():
                assert name in resolved, f"{name} есть в {source}, но нет в {compiled}"
                assert resolved[name] == version, (
                    f"{name}: {source} закрепляет {version}, "
                    f"{compiled} — {resolved[name]}"
                )

    def test_compiled_files_stay_generated(self) -> None:
        # Заголовок pip-compile — единственный признак того, что файл получен
        # инструментом, а не написан руками. Его исчезновение означает, что
        # предыдущая проверка сравнивает две рукописи.
        for compiled in ("requirements.txt", "requirements-dev.txt"):
            body = (REPO_ROOT / compiled).read_text(encoding="utf-8")
            assert "autogenerated by pip-compile" in body, compiled
            assert "--generate-hashes" in body, compiled

    def test_every_pin_carries_hashes(self) -> None:
        # Версия говорит, какой релиз брать, но не что внутри него лежит.
        # Подмена артефакта в уже выпущенной версии закреплением не ловится.
        for compiled in ("requirements.txt", "requirements-dev.txt"):
            body = (REPO_ROOT / compiled).read_text(encoding="utf-8")
            packages = len(_pins(compiled))
            hashes = body.count("--hash=sha256:")
            assert packages > 0, compiled
            assert hashes >= packages, (
                f"{compiled}: {packages} пакетов, но только {hashes} хешей"
            )


class TestInstallFlags:
    """Установка зависимостей не исполняет чужой код.

    Питоновский эквивалент A51 из основного репозитория. Колёса при установке
    код не исполняют, а sdist исполняет `setup.py`, то есть даёт произвольное
    выполнение от одного факта установки. `--only-binary=:all:` запрещает sdist
    целиком, `--require-hashes` не даёт тихо поставить непроверенное.
    """

    @pytest.mark.parametrize(("workflow", "body"), _workflows())
    def test_workflow_installs_are_guarded(self, workflow: str, body: str) -> None:
        payload = "\n".join(
            line for line in body.splitlines() if not line.lstrip().startswith("#")
        )
        for install in re.findall(r"^\s*pip install[^\n]*", payload, re.MULTILINE):
            assert "--require-hashes" in install, f"{workflow}: {install.strip()}"
            assert "--only-binary=:all:" in install, f"{workflow}: {install.strip()}"

    def test_dockerfile_install_is_guarded(self) -> None:
        body = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
        payload = "\n".join(
            line for line in body.splitlines() if not line.lstrip().startswith("#")
        )
        # Установка в образе одна, и она обязана нести оба флага.
        installs = re.findall(r"pip install[^\n]*(?:\\\n[^\n]*)*", payload)
        assert installs, "в Dockerfile не найдено ни одной установки"
        for install in installs:
            assert "--require-hashes" in install
            assert "--only-binary=:all:" in install

    def test_workflow_installs_are_found(self) -> None:
        # Предыдущие проверки проходят и на пустом списке совпадений.
        joined = "\n".join(body for _, body in _workflows())
        assert len(re.findall(r"^\s*pip install", joined, re.MULTILINE)) >= 2
