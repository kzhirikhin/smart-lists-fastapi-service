"""Проверки доказательств по файловой системе exact container image."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path
from typing import cast

import pytest

from scripts.verify_image_evidence import (
    CLAIM_CHECKS,
    EvidenceInputError,
    main,
    verify_image,
)


DIGEST = "sha256:" + "a" * 64
IMAGE_REF = f"us-central1-docker.pkg.dev/project/repository/insights-api@{DIGEST}"
EXPECTED_COMMAND = [
    "uvicorn",
    "app.main:app",
    "--host",
    "0.0.0.0",
    "--port",
    "8000",
]
BASE_STATUS = """\
Package: perl-base
Status: install ok installed
Version: 5.40.1-6

Package: gzip
Status: install ok installed
Version: 1.13-1

Package: libsqlite3-0
Status: install ok installed
Version: 3.46.1-7+deb13u1

Package: libacl1
Status: install ok installed
Version: 2.3.2-2+b1
"""
SAFE_APP = b"from fastapi import FastAPI\n\napp = FastAPI()\n"


def _write_inspect(
    path: Path,
    *,
    architecture: str = "amd64",
    user: str = "appuser",
    working_dir: str = "/app",
    entrypoint: list[str] | None = None,
    command: list[str] | None = None,
    repo_digests: list[str] | None = None,
) -> None:
    value = [
        {
            "Architecture": architecture,
            "RepoDigests": repo_digests if repo_digests is not None else [IMAGE_REF],
            "Config": {
                "User": user,
                "WorkingDir": working_dir,
                "Entrypoint": entrypoint,
                "Cmd": command if command is not None else EXPECTED_COMMAND,
            },
        }
    ]
    path.write_text(json.dumps(value), encoding="utf-8")


def _write_rootfs(
    path: Path,
    *,
    status: str = BASE_STATUS,
    app_source: bytes = SAFE_APP,
    extra_files: dict[str, bytes] | None = None,
    include_status: bool = True,
    include_root_member: bool = False,
    fstab_mode: int = 0o644,
    fstab_uid: int = 0,
    fstab_type: bytes = tarfile.REGTYPE,
    include_fstab: bool = True,
) -> None:
    files = {
        "app/app/main.py": app_source,
        "app/app/__init__.py": b"",
        "etc/fstab": b"# UNCONFIGURED FSTAB FOR BASE SYSTEM\n",
    }
    if include_status:
        files["var/lib/dpkg/status"] = status.encode()
    files.update(extra_files or {})
    if not include_fstab:
        files.pop("etc/fstab", None)

    with tarfile.open(path, mode="w") as archive:
        if include_root_member:
            root = tarfile.TarInfo(".")
            root.type = tarfile.DIRTYPE
            root.mode = 0o755
            archive.addfile(root)
        for name, payload in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = 0o644
            if name == "etc/fstab":
                info.mode = fstab_mode
                info.uid = fstab_uid
                info.type = fstab_type
                if fstab_type == tarfile.SYMTYPE:
                    info.linkname = "other-fstab"
                    info.size = 0
                    archive.addfile(info)
                    continue
            archive.addfile(info, io.BytesIO(payload))


def _fixture_files(tmp_path: Path, **rootfs_kwargs: object) -> tuple[Path, Path]:
    inspect_path = tmp_path / "inspect.json"
    rootfs_path = tmp_path / "rootfs.tar"
    _write_inspect(inspect_path)
    _write_rootfs(rootfs_path, **rootfs_kwargs)
    return inspect_path, rootfs_path


def _checks(report: dict[str, object]) -> dict[str, bool]:
    items = cast(list[dict[str, object]], report["checks"])
    return {
        cast(str, item["id"]): cast(bool, item["passed"])
        for item in items
    }


def test_safe_exact_image_passes_with_glibc_claims(tmp_path: Path) -> None:
    inspect_path, rootfs_path = _fixture_files(tmp_path)

    report = verify_image(inspect_path, rootfs_path, IMAGE_REF, DIGEST)

    assert report["status"] == "PASS"
    assert all(_checks(report).values())
    claims = report["candidateClaims"]
    assert len(claims) == len(CLAIM_CHECKS) == 27
    assert all(item["checksPassed"] for item in claims)
    assert {"CVE-2026-5435", "CVE-2026-5450", "CVE-2026-5928"} <= {
        item["vulnerabilityId"] for item in claims
    }


@pytest.mark.parametrize(
    ("source", "failed_check"),
    [
        (
            b"RESOLVER_SYMBOL = 'ns_sprintrrf'\n",
            "glibc_resolver_debug_functions_unreferenced",
        ),
        (
            b"SCAN_FORMAT = '%1025mc'\n",
            "glibc_scanf_large_mc_format_absent",
        ),
        (
            b"NATIVE_LIBRARY = 'libstdc++.so.6'\n",
            "glibc_ungetwc_runtime_surface_absent",
        ),
    ],
)
def test_glibc_runtime_precondition_fails_closed(
    tmp_path: Path,
    source: bytes,
    failed_check: str,
) -> None:
    inspect_path, rootfs_path = _fixture_files(tmp_path, app_source=source)

    report = verify_image(inspect_path, rootfs_path, IMAGE_REF, DIGEST)

    assert report["status"] == "FAIL"
    assert _checks(report)[failed_check] is False


def test_glibc_scanf_width_up_to_1024_is_not_vulnerable_condition(
    tmp_path: Path,
) -> None:
    inspect_path, rootfs_path = _fixture_files(
        tmp_path,
        app_source=b"SCAN_FORMAT = '%1024mc'\n",
    )

    report = verify_image(inspect_path, rootfs_path, IMAGE_REF, DIGEST)

    assert report["status"] == "PASS"
    assert _checks(report)["glibc_scanf_large_mc_format_absent"] is True


def test_invalid_runtime_elf_fails_closed(tmp_path: Path) -> None:
    inspect_path, rootfs_path = _fixture_files(
        tmp_path,
        extra_files={"usr/local/lib/broken.so": b"\x7fELF"},
    )

    report = verify_image(inspect_path, rootfs_path, IMAGE_REF, DIGEST)

    assert report["status"] == "FAIL"
    assert _checks(report)["native_elf_parseable"] is False


def test_root_directory_tar_member_is_accepted(tmp_path: Path) -> None:
    inspect_path, rootfs_path = _fixture_files(tmp_path, include_root_member=True)

    report = verify_image(inspect_path, rootfs_path, IMAGE_REF, DIGEST)

    assert report["status"] == "PASS"


def test_cli_writes_deterministic_pass_report(tmp_path: Path) -> None:
    inspect_path, rootfs_path = _fixture_files(tmp_path)
    output = tmp_path / "evidence.json"

    code = main(
        [
            "--inspect",
            str(inspect_path),
            "--rootfs-tar",
            str(rootfs_path),
            "--image-ref",
            IMAGE_REF,
            "--image-digest",
            DIGEST,
            "--output",
            str(output),
        ]
    )

    assert code == 0
    assert json.loads(output.read_text(encoding="utf-8"))["status"] == "PASS"


@pytest.mark.parametrize(
    ("field", "value", "failed_check"),
    [
        ("architecture", "i386", "architecture_amd64"),
        ("user", "root", "runtime_non_root"),
        ("working_dir", "/tmp", "runtime_entrypoint_exact"),
    ],
)
def test_runtime_metadata_mismatch_fails(
    tmp_path: Path,
    field: str,
    value: str,
    failed_check: str,
) -> None:
    inspect_path, rootfs_path = _fixture_files(tmp_path)
    _write_inspect(inspect_path, **{field: value})

    report = verify_image(inspect_path, rootfs_path, IMAGE_REF, DIGEST)

    assert report["status"] == "FAIL"
    assert _checks(report)[failed_check] is False


def test_inspect_must_contain_exact_repo_digest(tmp_path: Path) -> None:
    inspect_path, rootfs_path = _fixture_files(tmp_path)
    _write_inspect(inspect_path, repo_digests=[])

    report = verify_image(inspect_path, rootfs_path, IMAGE_REF, DIGEST)

    assert report["status"] == "FAIL"
    assert _checks(report)["image_digest_exact"] is False


@pytest.mark.parametrize("package", ["perl", "perl-modules-5.40", "libperl5.40"])
def test_full_perl_packages_fail_evidence(tmp_path: Path, package: str) -> None:
    status = BASE_STATUS + (
        f"\nPackage: {package}\nStatus: install ok installed\nVersion: 5.40.1-6\n"
    )
    inspect_path, rootfs_path = _fixture_files(tmp_path, status=status)

    report = verify_image(inspect_path, rootfs_path, IMAGE_REF, DIGEST)

    assert report["status"] == "FAIL"
    assert _checks(report)["perl_extended_packages_absent"] is False


@pytest.mark.parametrize(
    ("path", "failed_check"),
    [
        ("usr/share/perl/5.40.1/Archive/Tar.pm", "perl_archive_tar_absent"),
        ("usr/share/perl/5.40.1/IO/Uncompress/Unzip.pm", "perl_io_compress_absent"),
        ("usr/bin/zipdetails", "perl_zipdetails_absent"),
        ("usr/share/perl/5.40.1/File/GlobMapper.pm", "perl_glob_mapper_absent"),
        ("usr/lib/x86_64-linux-gnu/perl/5.40.1/Storable.pm", "perl_storable_absent"),
        ("usr/share/perl/5.40.1/HTTP/Tiny.pm", "perl_http_tiny_absent"),
    ],
)
def test_vulnerable_perl_component_path_fails(
    tmp_path: Path,
    path: str,
    failed_check: str,
) -> None:
    inspect_path, rootfs_path = _fixture_files(
        tmp_path,
        extra_files={path: b"module"},
    )

    report = verify_image(inspect_path, rootfs_path, IMAGE_REF, DIGEST)

    assert report["status"] == "FAIL"
    assert _checks(report)[failed_check] is False


@pytest.mark.parametrize(
    ("source", "failed_check"),
    [
        (b"import subprocess\n", "application_no_process_execution"),
        (b"import os\nos.system('true')\n", "application_no_process_execution"),
        (b"from os import execvp\nexecvp('x', [])\n", "application_no_process_execution"),
        (b"import sqlite3\n", "application_no_data_module_imports"),
        (
            b"import importlib\nimportlib.import_module('sqlite3')\n",
            "application_no_data_module_imports",
        ),
        (b"import ctypes\n", "application_no_native_library_loading"),
        (b"tool = 'infocmp'\n", "application_no_sensitive_command_literals"),
    ],
)
def test_application_runtime_path_violation_fails(
    tmp_path: Path,
    source: bytes,
    failed_check: str,
) -> None:
    inspect_path, rootfs_path = _fixture_files(tmp_path, app_source=source)

    report = verify_image(inspect_path, rootfs_path, IMAGE_REF, DIGEST)

    assert report["status"] == "FAIL"
    assert _checks(report)[failed_check] is False


def test_uninspected_application_binary_fails(tmp_path: Path) -> None:
    inspect_path, rootfs_path = _fixture_files(
        tmp_path,
        extra_files={"app/app/hidden.pyc": b"compiled"},
    )

    report = verify_image(inspect_path, rootfs_path, IMAGE_REF, DIGEST)

    assert report["status"] == "FAIL"
    assert _checks(report)["application_no_uninspected_code"] is False


def test_missing_dpkg_status_is_technical_error(tmp_path: Path) -> None:
    inspect_path, rootfs_path = _fixture_files(tmp_path, include_status=False)

    with pytest.raises(EvidenceInputError, match="dpkg/status"):
        verify_image(inspect_path, rootfs_path, IMAGE_REF, DIGEST)


def test_image_ref_and_digest_must_match_before_reading_files(tmp_path: Path) -> None:
    with pytest.raises(EvidenceInputError, match="точно привязан"):
        verify_image(
            tmp_path / "missing-inspect.json",
            tmp_path / "missing-rootfs.tar",
            IMAGE_REF,
            "sha256:" + "b" * 64,
        )

@pytest.mark.parametrize('rootfs_kwargs', [
    {'extra_files': {'etc/fstab': b'/src /dst none bind,user,X-mount.owner=10001 0 0\n'}},
    {'extra_files': {'etc/fstab': b'\xff'}},
    {'fstab_mode': 0o666},
    {'fstab_uid': 10001},
    {'fstab_type': tarfile.SYMTYPE},
    {'include_fstab': False},
])
def test_mount_configuration_fails_closed(tmp_path: Path, rootfs_kwargs: dict) -> None:
    inspect_path, rootfs_path = _fixture_files(tmp_path, **rootfs_kwargs)
    report = verify_image(inspect_path, rootfs_path, IMAGE_REF, DIGEST)
    assert report['status'] == 'FAIL'
    assert not _checks(report)['fstab_unconfigured']
    for claim in report['candidateClaims']:
        if claim['vulnerabilityId'] in {'CVE-2026-76642', 'CVE-2026-78409', 'CVE-2026-78410'}:
            assert not claim['checksPassed']


@pytest.mark.parametrize(('marker', 'check_id', 'cve'), [
    (b'libmount.so.1', 'libmount_runtime_surface_absent', 'CVE-2026-76642'),
    (b'mnt_context_mount', 'libmount_runtime_surface_absent', 'CVE-2026-78409'),
    (b'pcre2_dfa_match_8', 'pcre2_runtime_surface_absent', 'CVE-2026-86145'),
    (b'libpcre2-8.so.0', 'pcre2_runtime_surface_absent', 'CVE-2026-86145'),
    (b'gzwrite', 'zlib_gzwrite_runtime_surface_absent', 'CVE-2026-85091'),
    (b'gzprintf', 'zlib_gzwrite_runtime_surface_absent', 'CVE-2026-85091'),
    (b'gzvprintf', 'zlib_gzwrite_runtime_surface_absent', 'CVE-2026-85091'),
])
def test_new_native_path_in_dependency_invalidates_claim(
    tmp_path: Path, marker: bytes, check_id: str, cve: str,
) -> None:
    inspect_path, rootfs_path = _fixture_files(
        tmp_path, extra_files={'usr/local/lib/dependency.dat': marker},
    )
    report = verify_image(inspect_path, rootfs_path, IMAGE_REF, DIGEST)
    assert report['status'] == 'FAIL'
    assert not _checks(report)[check_id]
    assert not next(c for c in report['candidateClaims'] if c['vulnerabilityId'] == cve)['checksPassed']


@pytest.mark.parametrize('command', ['mount', 'nsenter', 'umount'])
def test_mount_command_literal_invalidates_runtime_claim(tmp_path: Path, command: str) -> None:
    inspect_path, rootfs_path = _fixture_files(tmp_path, app_source=f'COMMAND = {command!r}\n'.encode())
    report = verify_image(inspect_path, rootfs_path, IMAGE_REF, DIGEST)
    assert report['status'] == 'FAIL'
    assert not _checks(report)['application_no_sensitive_command_literals']
