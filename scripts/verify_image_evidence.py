"""Fail-closed проверка runtime-свойств точного container image.

Скрипт не запускает контейнер. Он читает результат ``docker image inspect``
и tar, полученный через ``docker create`` + ``docker export``. Поэтому отчёт
описывает байты конкретного digest, а не checkout, тег или предположение о
базовом образе.

PASS не подавляет CVE автоматически. Это только воспроизводимое техническое
доказательство, которое затем можно сослать из отдельно проверенного VEX.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import struct
import sys
import tarfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Callable


DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
EXPECTED_ARCHITECTURE = "amd64"
EXPECTED_USER = "appuser"
EXPECTED_WORKING_DIR = "/app"
EXPECTED_COMMAND = [
    "uvicorn",
    "app.main:app",
    "--host",
    "0.0.0.0",
    "--port",
    "8000",
]

# Эти пакеты содержат полную поставку Perl и модули, к которым относятся
# восемь текущих CVE. Минимальный perl-base сам по себе их не содержит.
FORBIDDEN_PERL_PACKAGES = {
    "perl",
    "perl-modules-5.40",
    "libperl5.40",
}

RELEVANT_PACKAGES = {
    "perl-base",
    "perl",
    "perl-modules-5.40",
    "libperl5.40",
    "gzip",
    "libacl1",
    "libsqlite3-0",
    "libc6",
    "libc-bin",
    "ncurses-bin",
    "ncurses-base",
    "libncursesw6",
    "libtinfo6",
}

PROCESS_MODULES = {"subprocess", "pexpect"}
DATA_MODULES = {"sqlite3", "tarfile", "gzip", "zipfile"}
NATIVE_MODULES = {"ctypes", "cffi"}
SENSITIVE_COMMANDS = re.compile(
    r"(?<![A-Za-z0-9_.-])"
    r"(?:perl(?:5\.40\.1)?|gzip|infocmp|zipdetails|setfacl|getfacl|chacl)"
    r"(?![A-Za-z0-9_.-])"
)

SENSITIVE_CALLS = {
    "os.system",
    "os.popen",
    "asyncio.create_subprocess_exec",
    "asyncio.create_subprocess_shell",
    "anyio.open_process",
    "anyio.run_process",
    "trio.open_process",
    "trio.run_process",
}

ELF_MAGIC = b"\x7fELF"
RUNTIME_PREFIXES = ("app/", "usr/local/")
GLIBC_RESOLVER_SYMBOLS = {
    "fp_nquery",
    "__fp_nquery",
    "ns_printrr",
    "ns_printrrf",
    "ns_sprintrr",
    "ns_sprintrrf",
    "__ns_sprintrr",
    "__ns_sprintrrf",
    "___ns_sprintrr",
    "___ns_sprintrrf",
}
GLIBC_RESOLVER_PROVIDERS = {
    "usr/lib/x86_64-linux-gnu/libc.so.6",
    "usr/lib/x86_64-linux-gnu/libresolv.so.2",
}
GLIBC_LARGE_MC_FORMAT = re.compile(rb"%(?:[1-9][0-9]*\$)?([0-9]+)mc")
GLIBC_UNGETWC_MARKERS = (b"ungetwc", b"libstdc++.so.6")

# В отчёте явно видно, какие проверки поддерживают будущий VEX.
CLAIM_CHECKS: dict[str, tuple[str, ...]] = {
    "CVE-2026-42496": ("perl_extended_packages_absent", "perl_archive_tar_absent"),
    "CVE-2026-42497": ("perl_extended_packages_absent", "perl_archive_tar_absent"),
    "CVE-2026-9538": ("perl_extended_packages_absent", "perl_archive_tar_absent"),
    "CVE-2026-48959": ("perl_extended_packages_absent", "perl_io_compress_absent"),
    "CVE-2026-48961": ("perl_extended_packages_absent", "perl_zipdetails_absent"),
    "CVE-2026-48962": ("perl_extended_packages_absent", "perl_glob_mapper_absent"),
    "CVE-2026-57433": ("perl_extended_packages_absent", "perl_storable_absent"),
    "CVE-2026-7017": ("perl_extended_packages_absent", "perl_http_tiny_absent"),
    "CVE-2026-8376": ("architecture_amd64",),
    "CVE-2026-12087": (
        "runtime_entrypoint_exact",
        "application_no_process_execution",
        "application_no_sensitive_command_literals",
    ),
    "CVE-2026-13221": (
        "runtime_entrypoint_exact",
        "application_no_process_execution",
        "application_no_sensitive_command_literals",
    ),
    "CVE-2026-57432": (
        "runtime_entrypoint_exact",
        "application_no_process_execution",
        "application_no_sensitive_command_literals",
    ),
    "CVE-2025-69720": (
        "runtime_entrypoint_exact",
        "application_no_process_execution",
        "application_no_sensitive_command_literals",
    ),
    "CVE-2026-41992": (
        "runtime_entrypoint_exact",
        "application_no_process_execution",
        "application_no_sensitive_command_literals",
    ),
    "CVE-2026-11822": (
        "runtime_entrypoint_exact",
        "application_no_data_module_imports",
    ),
    "CVE-2026-11824": (
        "runtime_entrypoint_exact",
        "application_no_data_module_imports",
    ),
    "CVE-2026-54369": (
        "runtime_non_root",
        "application_no_process_execution",
        "application_no_native_library_loading",
        "application_no_sensitive_command_literals",
    ),
    "CVE-2026-54370": (
        "runtime_non_root",
        "application_no_process_execution",
        "application_no_native_library_loading",
        "application_no_sensitive_command_literals",
    ),
    "CVE-2026-5435": (
        "runtime_entrypoint_exact",
        "application_no_process_execution",
        "application_no_native_library_loading",
        "native_elf_parseable",
        "glibc_resolver_debug_functions_unreferenced",
    ),
    "CVE-2026-5450": (
        "runtime_entrypoint_exact",
        "application_no_process_execution",
        "application_no_native_library_loading",
        "native_elf_parseable",
        "glibc_scanf_large_mc_format_absent",
    ),
    "CVE-2026-5928": (
        "runtime_entrypoint_exact",
        "application_no_process_execution",
        "application_no_native_library_loading",
        "native_elf_parseable",
        "glibc_ungetwc_runtime_surface_absent",
    ),
}


class EvidenceInputError(ValueError):
    """Входные данные нельзя безопасно проверить."""


@dataclass(frozen=True)
class Check:
    """Один проверяемый факт без исходного содержимого файлов."""

    id: str
    passed: bool
    detail: str


def _normalise_tar_name(name: str) -> str | None:
    normalised = PurePosixPath(name.removeprefix("./")).as_posix().lstrip("/")
    if normalised in {"", "."}:
        return None
    if ".." in PurePosixPath(normalised).parts:
        raise EvidenceInputError(f"небезопасный путь в rootfs tar: {name!r}")
    return normalised


def _load_inspect(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceInputError(f"docker inspect JSON не прочитан: {exc}") from exc
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise EvidenceInputError("docker inspect должен содержать один image object")
    return value[0]


def _read_tar_file(
    archive: tarfile.TarFile,
    members: dict[str, tarfile.TarInfo],
    name: str,
    *,
    max_bytes: int,
) -> bytes:
    member = members.get(name)
    if member is None or not member.isfile():
        raise EvidenceInputError(f"в rootfs отсутствует обычный файл /{name}")
    if member.size > max_bytes:
        raise EvidenceInputError(f"/{name} превышает допустимый размер проверки")
    source = archive.extractfile(member)
    if source is None:
        raise EvidenceInputError(f"/{name} не удалось прочитать")
    data = source.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise EvidenceInputError(f"/{name} превышает допустимый размер проверки")
    return data


def _installed_packages(status: str) -> dict[str, str]:
    packages: dict[str, str] = {}
    for stanza in re.split(r"\n\s*\n", status.strip()):
        fields: dict[str, str] = {}
        for line in stanza.splitlines():
            if ":" not in line or line[:1].isspace():
                continue
            key, value = line.split(":", 1)
            fields[key] = value.strip()
        if fields.get("Status") != "install ok installed":
            continue
        name = fields.get("Package")
        version = fields.get("Version")
        if name and version:
            packages[name] = version
    if not packages:
        raise EvidenceInputError("dpkg status не содержит установленных пакетов")
    return packages


def _dotted_name(node: ast.expr, aliases: dict[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value, aliases)
        return f"{base}.{node.attr}" if base else None
    return None


def _analyse_python(path: str, source: bytes) -> dict[str, list[str]]:
    try:
        text = source.decode("utf-8")
        tree = ast.parse(text, filename=f"/{path}")
    except (UnicodeDecodeError, SyntaxError) as exc:
        return {"syntax": [f"{path}: {exc}"]}

    aliases: dict[str, str] = {}
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                root = item.name.split(".", 1)[0]
                aliases[item.asname or root] = item.name
                imported_roots.add(root)
        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".", 1)[0]
            imported_roots.add(root)
            for item in node.names:
                aliases[item.asname or item.name] = f"{node.module}.{item.name}"

    process_calls: list[str] = []
    dynamic_process_imports: list[str] = []
    dynamic_data_imports: list[str] = []
    dynamic_native_imports: list[str] = []
    sensitive_literals: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            called = _dotted_name(node.func, aliases)
            if called in SENSITIVE_CALLS or (
                called is not None
                and (called.startswith("os.exec") or called.startswith("os.spawn"))
            ):
                process_calls.append(f"{path}:{node.lineno}:{called}")
            if called in {"importlib.import_module", "__import__"} and node.args:
                argument = node.args[0]
                if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                    root = argument.value.split(".", 1)[0]
                    finding = f"{path}:{node.lineno}:{root}"
                    if root in PROCESS_MODULES:
                        dynamic_process_imports.append(finding)
                    elif root in DATA_MODULES:
                        dynamic_data_imports.append(finding)
                    elif root in NATIVE_MODULES:
                        dynamic_native_imports.append(finding)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            match = SENSITIVE_COMMANDS.search(node.value)
            if match:
                sensitive_literals.append(f"{path}:{node.lineno}:{match.group(0)}")

    return {
        "syntax": [],
        "process_imports": sorted(imported_roots & PROCESS_MODULES),
        "data_imports": sorted(imported_roots & DATA_MODULES),
        "native_imports": sorted(imported_roots & NATIVE_MODULES),
        "process_calls": sorted(process_calls),
        "dynamic_process_imports": sorted(dynamic_process_imports),
        "dynamic_data_imports": sorted(dynamic_data_imports),
        "dynamic_native_imports": sorted(dynamic_native_imports),
        "sensitive_literals": sorted(sensitive_literals),
    }


def _c_string(table: bytes, offset: int) -> str:
    if offset >= len(table):
        return ""
    end = table.find(b"\0", offset)
    if end < 0:
        end = len(table)
    return table[offset:end].decode("ascii", errors="replace")


def _undefined_elf_symbols(data: bytes) -> set[str]:
    """Прочитать undefined dynamic symbols из ELF64 little-endian без запуска кода."""

    if len(data) < 64 or data[:4] != ELF_MAGIC:
        raise EvidenceInputError("усечённый ELF header")
    if data[4] != 2 or data[5] != 1:
        raise EvidenceInputError("ожидался ELF64 little-endian")

    section_offset = struct.unpack_from("<Q", data, 40)[0]
    section_entry_size = struct.unpack_from("<H", data, 58)[0]
    section_count = struct.unpack_from("<H", data, 60)[0]
    if section_count == 0:
        raise EvidenceInputError("ELF без обычной section table не поддерживается")
    if section_entry_size < 64:
        raise EvidenceInputError("некорректный размер ELF section header")
    if section_offset + section_entry_size * section_count > len(data):
        raise EvidenceInputError("усечённая ELF section table")

    sections = [
        struct.unpack_from(
            "<IIQQQQIIQQ",
            data,
            section_offset + index * section_entry_size,
        )
        for index in range(section_count)
    ]
    result: set[str] = set()
    for section in sections:
        if section[1] != 11:  # SHT_DYNSYM
            continue
        symbols_offset, symbols_size, strings_index, symbol_size = (
            section[4],
            section[5],
            section[6],
            section[9] or 24,
        )
        if strings_index >= len(sections) or symbol_size < 24:
            raise EvidenceInputError("некорректная ELF dynamic symbol table")
        if symbols_offset + symbols_size > len(data):
            raise EvidenceInputError("усечённая ELF dynamic symbol table")

        strings_section = sections[strings_index]
        strings_offset, strings_size = strings_section[4], strings_section[5]
        if strings_offset + strings_size > len(data):
            raise EvidenceInputError("усечённая ELF dynamic string table")
        strings = data[strings_offset : strings_offset + strings_size]

        for symbol_offset in range(
            symbols_offset,
            symbols_offset + symbols_size,
            symbol_size,
        ):
            if symbol_offset + 24 > len(data):
                raise EvidenceInputError("усечённый ELF dynamic symbol")
            name_offset, _, _, section_index, _, _ = struct.unpack_from(
                "<IBBHQQ", data, symbol_offset
            )
            if section_index == 0:
                name = _c_string(strings, name_offset)
                if name:
                    result.add(name)
    return result


def verify_image(
    inspect_path: Path,
    rootfs_tar: Path,
    image_ref: str,
    image_digest: str,
) -> dict[str, object]:
    """Проверить точный image и вернуть детерминированный JSON-отчёт."""

    if not DIGEST.fullmatch(image_digest):
        raise EvidenceInputError("image digest должен иметь вид sha256:<64 lowercase hex>")
    if "@" not in image_ref or image_ref.rsplit("@", 1)[1] != image_digest:
        raise EvidenceInputError("image ref должен быть точно привязан к переданному digest")

    inspected = _load_inspect(inspect_path)
    config_value = inspected.get("Config")
    if not isinstance(config_value, dict):
        raise EvidenceInputError("docker inspect не содержит Config")
    config = config_value
    repo_digests = inspected.get("RepoDigests")
    if not isinstance(repo_digests, list):
        repo_digests = []

    checks: list[Check] = []

    def record(check_id: str, passed: bool, detail: str) -> None:
        checks.append(Check(check_id, passed, detail))

    record(
        "image_digest_exact",
        image_ref in repo_digests,
        "RepoDigests содержит точный проверяемый image ref"
        if image_ref in repo_digests
        else "точный image ref отсутствует в RepoDigests",
    )
    architecture = inspected.get("Architecture")
    record(
        "architecture_amd64",
        architecture == EXPECTED_ARCHITECTURE,
        f"architecture={architecture!r}",
    )
    user = config.get("User")
    record("runtime_non_root", user == EXPECTED_USER, f"user={user!r}")
    command = config.get("Cmd")
    entrypoint = config.get("Entrypoint")
    working_dir = config.get("WorkingDir")
    entrypoint_ok = (
        command == EXPECTED_COMMAND
        and entrypoint in (None, [])
        and working_dir == EXPECTED_WORKING_DIR
    )
    record(
        "runtime_entrypoint_exact",
        entrypoint_ok,
        f"workingDir={working_dir!r}, entrypoint={entrypoint!r}, cmd={command!r}",
    )

    try:
        archive = tarfile.open(rootfs_tar, mode="r:*")
    except (OSError, tarfile.TarError) as exc:
        raise EvidenceInputError(f"rootfs tar не прочитан: {exc}") from exc

    with archive:
        members: dict[str, tarfile.TarInfo] = {}
        for member in archive.getmembers():
            name = _normalise_tar_name(member.name)
            if name is None:
                continue
            if name in members:
                raise EvidenceInputError(f"повторный путь в rootfs tar: /{name}")
            members[name] = member

        status_bytes = _read_tar_file(
            archive,
            members,
            "var/lib/dpkg/status",
            max_bytes=10 * 1024 * 1024,
        )
        try:
            packages = _installed_packages(status_bytes.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise EvidenceInputError("dpkg status не является UTF-8") from exc

        present_forbidden = sorted(FORBIDDEN_PERL_PACKAGES & packages.keys())
        record(
            "perl_extended_packages_absent",
            not present_forbidden,
            "полные Perl-пакеты отсутствуют"
            if not present_forbidden
            else f"установлены: {', '.join(present_forbidden)}",
        )

        names = set(members)

        def absent(
            check_id: str,
            predicate: Callable[[str], bool],
            description: str,
        ) -> None:
            matches = sorted(name for name in names if predicate(name))
            record(
                check_id,
                not matches,
                f"{description}: отсутствует"
                if not matches
                else f"{description}: найдено {matches[:3]!r}",
            )

        absent(
            "perl_archive_tar_absent",
            lambda name: name.endswith("/Archive/Tar.pm"),
            "Archive::Tar",
        )
        absent(
            "perl_io_compress_absent",
            lambda name: "/IO/Uncompress/" in f"/{name}"
            or name.endswith("/IO/Uncompress.pm"),
            "IO::Uncompress",
        )
        absent(
            "perl_zipdetails_absent",
            lambda name: name in {"usr/bin/zipdetails", "bin/zipdetails"},
            "zipdetails",
        )
        absent(
            "perl_glob_mapper_absent",
            lambda name: name.endswith("/File/GlobMapper.pm"),
            "File::GlobMapper",
        )
        absent(
            "perl_storable_absent",
            lambda name: name.endswith("/Storable.pm")
            or "/auto/Storable/" in f"/{name}",
            "Storable",
        )
        absent(
            "perl_http_tiny_absent",
            lambda name: name.endswith("/HTTP/Tiny.pm"),
            "HTTP::Tiny",
        )

        app_prefix = "app/app/"
        app_sources = sorted(
            name
            for name, member in members.items()
            if name.startswith(app_prefix) and name.endswith(".py") and member.isfile()
        )
        sources_present = "app/app/main.py" in app_sources and bool(app_sources)
        record(
            "application_sources_present",
            sources_present,
            f"проверено Python-файлов: {len(app_sources)}",
        )

        uninspected = sorted(
            name
            for name, member in members.items()
            if name.startswith(app_prefix)
            and member.isfile()
            and name.endswith((".pyc", ".pyo", ".so"))
        )
        record(
            "application_no_uninspected_code",
            not uninspected,
            "в /app/app нет pyc/pyo/native modules"
            if not uninspected
            else f"непроверенный исполняемый код: {uninspected[:5]!r}",
        )

        aggregate: dict[str, list[str]] = {
            "syntax": [],
            "process_imports": [],
            "data_imports": [],
            "native_imports": [],
            "process_calls": [],
            "dynamic_process_imports": [],
            "dynamic_data_imports": [],
            "dynamic_native_imports": [],
            "sensitive_literals": [],
        }
        for source_path in app_sources:
            source = _read_tar_file(
                archive,
                members,
                source_path,
                max_bytes=2 * 1024 * 1024,
            )
            result = _analyse_python(source_path, source)
            for key, values in result.items():
                aggregate[key].extend(values)

        syntax_ok = not aggregate["syntax"]
        record(
            "application_python_parseable",
            syntax_ok,
            "все application Python-файлы разобраны AST"
            if syntax_ok
            else f"ошибки разбора: {aggregate['syntax'][:3]!r}",
        )
        process_violations = sorted(
            set(
                aggregate["process_imports"]
                + aggregate["process_calls"]
                + aggregate["dynamic_process_imports"]
            )
        )
        record(
            "application_no_process_execution",
            not process_violations,
            "нет импортов и вызовов запуска процессов"
            if not process_violations
            else f"найдено: {process_violations[:5]!r}",
        )
        record(
            "application_no_data_module_imports",
            not (aggregate["data_imports"] or aggregate["dynamic_data_imports"]),
            "нет импортов SQLite/archive modules"
            if not (aggregate["data_imports"] or aggregate["dynamic_data_imports"])
            else "найдено: "
            f"{sorted(set(aggregate['data_imports'] + aggregate['dynamic_data_imports']))!r}",
        )
        record(
            "application_no_native_library_loading",
            not (aggregate["native_imports"] or aggregate["dynamic_native_imports"]),
            "нет прямой загрузки native libraries"
            if not (aggregate["native_imports"] or aggregate["dynamic_native_imports"])
            else "найдено: "
            f"{sorted(set(aggregate['native_imports'] + aggregate['dynamic_native_imports']))!r}",
        )
        record(
            "application_no_sensitive_command_literals",
            not aggregate["sensitive_literals"],
            "имена уязвимых CLI отсутствуют в строковых литералах приложения"
            if not aggregate["sensitive_literals"]
            else f"найдено: {aggregate['sensitive_literals'][:5]!r}",
        )

        elf_count = 0
        elf_errors: list[str] = []
        resolver_references: list[str] = []
        large_mc_formats: list[str] = []
        runtime_ungetwc_references: list[str] = []
        resolver_markers = {
            symbol: symbol.encode("ascii") for symbol in GLIBC_RESOLVER_SYMBOLS
        }

        for name, member in sorted(members.items()):
            if not member.isfile():
                continue
            data = _read_tar_file(
                archive,
                members,
                name,
                max_bytes=256 * 1024 * 1024,
            )
            runtime_file = name.startswith(RUNTIME_PREFIXES)

            for match in GLIBC_LARGE_MC_FORMAT.finditer(data):
                width = int(match.group(1))
                if width > 1024:
                    large_mc_formats.append(f"/{name}:%{width}mc")

            if runtime_file:
                for marker in GLIBC_UNGETWC_MARKERS:
                    if marker in data:
                        runtime_ungetwc_references.append(
                            f"/{name}:{marker.decode('ascii')}"
                        )
                for symbol, marker in resolver_markers.items():
                    if marker in data:
                        resolver_references.append(f"/{name}:{symbol}")

            if data[:4] != ELF_MAGIC:
                continue
            elf_count += 1
            try:
                undefined_symbols = _undefined_elf_symbols(data)
            except EvidenceInputError as exc:
                elf_errors.append(f"/{name}: {exc}")
                continue

            for symbol in sorted(GLIBC_RESOLVER_SYMBOLS & undefined_symbols):
                resolver_references.append(f"/{name}:{symbol}")
            if name not in GLIBC_RESOLVER_PROVIDERS:
                for symbol, marker in resolver_markers.items():
                    if marker in data:
                        resolver_references.append(f"/{name}:{symbol}")

            if runtime_file and "ungetwc" in undefined_symbols:
                runtime_ungetwc_references.append(f"/{name}:ungetwc")

        resolver_references = sorted(set(resolver_references))
        runtime_ungetwc_references = sorted(set(runtime_ungetwc_references))
        large_mc_formats = sorted(set(large_mc_formats))
        record(
            "native_elf_parseable",
            not elf_errors,
            f"без исполнения разобрано ELF-файлов: {elf_count}"
            if not elf_errors
            else f"ошибки ELF-разбора: {elf_errors[:5]!r}",
        )
        record(
            "glibc_resolver_debug_functions_unreferenced",
            not resolver_references,
            "вне libc/libresolv нет импортов или runtime-ссылок на уязвимые DNS-print функции"
            if not resolver_references
            else f"найдены ссылки: {resolver_references[:5]!r}",
        )
        record(
            "glibc_scanf_large_mc_format_absent",
            not large_mc_formats,
            "во всём exact rootfs нет формата %mc с явной шириной больше 1024"
            if not large_mc_formats
            else f"найдены форматы: {large_mc_formats[:5]!r}",
        )
        record(
            "glibc_ungetwc_runtime_surface_absent",
            not runtime_ungetwc_references,
            "в /app и /usr/local нет вызовов ungetwc или загрузки libstdc++"
            if not runtime_ungetwc_references
            else f"найдены runtime-ссылки: {runtime_ungetwc_references[:5]!r}",
        )

    passed_by_id = {check.id: check.passed for check in checks}
    claims = [
        {
            "vulnerabilityId": vulnerability_id,
            "evidenceChecks": list(required_checks),
            "checksPassed": all(
                passed_by_id.get(check_id, False) for check_id in required_checks
            ),
        }
        for vulnerability_id, required_checks in sorted(CLAIM_CHECKS.items())
    ]
    overall_passed = all(check.passed for check in checks) and all(
        claim["checksPassed"] for claim in claims
    )
    selected_packages = {
        name: packages[name] for name in sorted(RELEVANT_PACKAGES & packages.keys())
    }
    return {
        "schemaVersion": 1,
        "imageRef": image_ref,
        "imageDigest": image_digest,
        "status": "PASS" if overall_passed else "FAIL",
        "execution": "not_run; inspected via docker image inspect/create/export",
        "facts": {
            "architecture": architecture,
            "user": user,
            "workingDir": working_dir,
            "entrypoint": entrypoint,
            "command": command,
            "relevantPackages": selected_packages,
            "applicationSources": app_sources,
        },
        "checks": [asdict(check) for check in checks],
        "candidateClaims": claims,
    }


def _write_json(path: Path, value: dict[str, object]) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inspect", type=Path, required=True)
    parser.add_argument("--rootfs-tar", type=Path, required=True)
    parser.add_argument("--image-ref", required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        report = verify_image(
            args.inspect,
            args.rootfs_tar,
            args.image_ref,
            args.image_digest,
        )
    except EvidenceInputError as exc:
        report = {
            "schemaVersion": 1,
            "imageRef": args.image_ref,
            "imageDigest": args.image_digest,
            "status": "ERROR",
            "errors": [str(exc)],
        }
        _write_json(args.output, report)
        print(f"image evidence error: {exc}", file=sys.stderr)
        return 2

    _write_json(args.output, report)
    if report["status"] != "PASS":
        print("image evidence mismatch", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
