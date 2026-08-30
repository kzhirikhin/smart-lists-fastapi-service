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
) -> None:
    files = {
        "app/app/main.py": app_source,
        "app/app/__init__.py": b"",
    }
    if include_status:
        files["var/lib/dpkg/status"] = status.encode()
    files.update(extra_files or {})

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


def test_safe_exact_image_passes_without_glibc_claims(tmp_path: Path) -> None:
    inspect_path, rootfs_path = _fixture_files(tmp_path)

    report = verify_image(inspect_path, rootfs_path, IMAGE_REF, DIGEST)

    assert report["status"] == "PASS"
    assert all(_checks(report).values())
    claims = report["candidateClaims"]
    assert len(claims) == len(CLAIM_CHECKS) == 18
    assert all(item["checksPassed"] for item in claims)
    assert {item["vulnerabilityId"] for item in claims}.isdisjoint(
        {"CVE-2026-5435", "CVE-2026-5450", "CVE-2026-5928"}
    )


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
