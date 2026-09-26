"""Контракты VEX/waiver для периодического сканирования образа."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from scripts.evaluate_image_scan import (
    ADVISORY_FIX_STATES,
    ADVISORY_SEVERITIES,
    Finding,
    PackageKey,
    PolicyError,
    PolicyKey,
    Rule,
    evaluate,
    load_findings,
    load_vex_rules,
    load_waiver_rules,
    main,
    render_summary,
)

NOW = datetime(2026, 8, 29, 15, tzinfo=UTC)
DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64
PURL = "pkg:deb/debian/libc6@2.41-12%2Bdeb13u3?arch=amd64&distro=debian-13.6"
PACKAGE = PackageKey("CVE-2026-5450", "libc6", "2.41-12+deb13u3", PURL)


def _finding(severity: str = "Critical") -> Finding:
    return Finding(key=PACKAGE, severity=severity)


def test_repository_vex_documents_are_valid() -> None:
    """Каждый закоммиченный VEX обязан проходить тот же строгий parser, что и scan."""
    rules = load_vex_rules(Path("security/vex"), datetime.now(UTC))

    assert all(rule.mechanism == "vex_not_affected" for rule in rules)


def _vex_document(*, state: str = "not_affected", evidence: bool = True) -> dict:
    properties = []
    if evidence:
        properties.append(
            {
                "name": "smart-lists:vex:evidence",
                "value": "https://github.com/owner/repository/blob/commit/test.py",
            }
        )
    return {
        "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:11111111-1111-4111-8111-111111111111",
        "version": 1,
        "metadata": {
            "timestamp": "2026-08-29T14:00:00Z",
            "component": {
                "bom-ref": f"pkg:oci/insights-api@{DIGEST}",
                "type": "container",
                "name": "insights-api",
                "version": DIGEST,
            },
            "properties": [
                {"name": "smart-lists:vex:reviewed-by", "value": "@kirill"},
                {
                    "name": "smart-lists:vex:reviewed-at",
                    "value": "2026-08-29T14:00:00Z",
                },
                {
                    "name": "smart-lists:vex:approval",
                    "value": "https://github.com/kzhirikhin/smart-lists-fastapi-service/pull/1",
                },
            ],
        },
        "components": [
            {
                "bom-ref": PURL,
                "type": "library",
                "name": PACKAGE.name,
                "version": PACKAGE.version,
                "purl": PURL,
            }
        ],
        "vulnerabilities": [
            {
                "id": PACKAGE.vulnerability_id,
                "analysis": {
                    "state": state,
                    "justification": "code_not_reachable",
                    "detail": (
                        "Проверен конкретный уязвимый путь вызова и тестом доказано, "
                        "что он недостижим в конфигурации именно этого образа."
                    ),
                },
                "affects": [{"ref": PURL}],
                "properties": properties,
            }
        ],
    }


def _waiver_document(
    *,
    approved_at: str = "2026-08-28T12:00:00Z",
    expires_at: str = "2026-09-10T12:00:00Z",
    digest: str = DIGEST,
) -> dict:
    return {
        "schemaVersion": 1,
        "waivers": [
            {
                "id": "WAIVER-2026-001",
                "vulnerabilityId": PACKAGE.vulnerability_id,
                "imageDigest": digest,
                "package": {
                    "name": PACKAGE.name,
                    "version": PACKAGE.version,
                    "purl": PACKAGE.purl,
                },
                "reason": (
                    "Уязвимость реальна, но немедленное обновление ломает совместимость; "
                    "доступ к сервису ограничен Cloud Run IAM."
                ),
                "remediationPlan": (
                    "Обновить базовый образ после выхода совместимого Debian-пакета."
                ),
                "owner": "@kirill",
                "approvedBy": "@kirill",
                "approval": "https://github.com/kzhirikhin/smart-lists-fastapi-service/pull/2",
                "evidence": ["https://security-tracker.debian.org/tracker/CVE-2026-5450"],
                "approvedAt": approved_at,
                "expiresAt": expires_at,
            }
        ],
    }


def _write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def test_high_without_exception_blocks() -> None:
    result = evaluate([_finding()], DIGEST, [], [], [], NOW)

    assert result["gate"]["passed"] is False
    assert result["summary"]["remainingCritical"] == 1
    assert result["suppressed"] == []


def test_only_exact_vex_rule_suppresses() -> None:
    rule = Rule(PolicyKey(DIGEST, PACKAGE), "vex_not_affected", "vex-1")

    allowed = evaluate([_finding()], DIGEST, [rule], [], [], NOW)
    wrong_digest = evaluate([_finding()], OTHER_DIGEST, [rule], [], [], NOW)

    assert allowed["gate"]["passed"] is True
    assert allowed["summary"]["vexSuppressed"] == 1
    assert wrong_digest["gate"]["passed"] is False


def test_valid_cyclonedx_vex_loads_and_matches(tmp_path: Path) -> None:
    vex_dir = tmp_path / "vex"
    vex_dir.mkdir()
    _write_json(vex_dir / f"{'a' * 64}.cdx.json", _vex_document())

    rules = load_vex_rules(vex_dir, NOW)
    result = evaluate([_finding()], DIGEST, rules, [], [], NOW)

    assert len(rules) == 1
    assert result["gate"]["passed"] is True
    assert result["summary"]["vexSuppressed"] == 1


@pytest.mark.parametrize("state", ["in_triage", "exploitable", "resolved"])
def test_vex_rejects_every_state_except_not_affected(
    tmp_path: Path, state: str
) -> None:
    vex_dir = tmp_path / "vex"
    vex_dir.mkdir()
    _write_json(vex_dir / f"{'a' * 64}.cdx.json", _vex_document(state=state))

    with pytest.raises(PolicyError, match="только not_affected"):
        load_vex_rules(vex_dir, NOW)


def test_vex_requires_external_evidence(tmp_path: Path) -> None:
    vex_dir = tmp_path / "vex"
    vex_dir.mkdir()
    _write_json(vex_dir / f"{'a' * 64}.cdx.json", _vex_document(evidence=False))

    with pytest.raises(PolicyError, match="evidence URL"):
        load_vex_rules(vex_dir, NOW)


def test_active_waiver_suppresses_exact_finding(tmp_path: Path) -> None:
    path = tmp_path / "waivers.json"
    _write_json(path, _waiver_document())
    active, expired = load_waiver_rules(path, NOW)

    result = evaluate([_finding()], DIGEST, [], active, expired, NOW)

    assert result["gate"]["passed"] is True
    assert result["summary"]["waiverSuppressed"] == 1


def test_expired_waiver_is_visible_but_does_not_suppress(tmp_path: Path) -> None:
    path = tmp_path / "waivers.json"
    _write_json(
        path,
        _waiver_document(
            approved_at="2026-08-01T12:00:00Z",
            expires_at="2026-08-20T12:00:00Z",
        ),
    )
    active, expired = load_waiver_rules(path, NOW)

    result = evaluate([_finding()], DIGEST, [], active, expired, NOW)

    assert result["gate"]["passed"] is False
    assert result["summary"]["expiredWaiverMatches"] == 1


def test_waiver_longer_than_30_days_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "waivers.json"
    _write_json(
        path,
        _waiver_document(
            approved_at="2026-08-01T12:00:00Z",
            expires_at="2026-09-01T12:00:01Z",
        ),
    )

    with pytest.raises(PolicyError, match="дольше 30 дней"):
        load_waiver_rules(path, NOW)


def test_waiver_rejects_blanket_package_name(tmp_path: Path) -> None:
    path = tmp_path / "waivers.json"
    document = _waiver_document()
    document["waivers"][0]["package"]["name"] = "*"
    _write_json(path, document)

    with pytest.raises(PolicyError, match="wildcard"):
        load_waiver_rules(path, NOW)


def test_vex_and_active_waiver_cannot_overlap() -> None:
    vex = Rule(PolicyKey(DIGEST, PACKAGE), "vex_not_affected", "vex-1")
    waiver = Rule(PolicyKey(DIGEST, PACKAGE), "temporary_waiver", "WAIVER-2026-001")

    with pytest.raises(PolicyError, match="одновременно покрыта"):
        evaluate([_finding()], DIGEST, [vex], [waiver], [], NOW)


def test_only_high_with_explicit_unfixable_state_is_advisory() -> None:
    """Расширение послабления — осознанное изменение политики, а не правка константы."""
    assert ADVISORY_FIX_STATES == {"not-fixed", "wont-fix"}
    assert ADVISORY_SEVERITIES == {"High"}


@pytest.mark.parametrize("state", ["not-fixed", "wont-fix"])
def test_unfixable_high_is_reported_but_does_not_block(state: str) -> None:
    finding = Finding(key=PACKAGE, severity="High", fix_state=state)

    result = evaluate([finding], DIGEST, [], [], [], NOW)

    assert result["gate"]["passed"] is True
    assert result["remaining"] == []
    assert result["summary"]["advisoryHigh"] == 1
    assert result["advisory"][0]["fixState"] == state


@pytest.mark.parametrize("state", ["fixed", "unknown", "", "some-future-state"])
def test_high_with_fix_or_unclear_state_blocks(state: str) -> None:
    """Неизвестное не считается неисправимым: gate ослабляется только явно."""
    finding = Finding(key=PACKAGE, severity="High", fix_state=state)

    result = evaluate([finding], DIGEST, [], [], [], NOW)

    assert result["gate"]["passed"] is False
    assert result["summary"]["remainingHigh"] == 1
    assert result["advisory"] == []


@pytest.mark.parametrize("state", ["not-fixed", "wont-fix", "fixed", ""])
def test_critical_blocks_regardless_of_fix_state(state: str) -> None:
    finding = Finding(key=PACKAGE, severity="Critical", fix_state=state)

    result = evaluate([finding], DIGEST, [], [], [], NOW)

    assert result["gate"]["passed"] is False
    assert result["summary"]["remainingCritical"] == 1
    assert result["advisory"] == []


def test_vex_still_suppresses_unfixable_high() -> None:
    rule = Rule(PolicyKey(DIGEST, PACKAGE), "vex_not_affected", "vex-1")
    finding = Finding(key=PACKAGE, severity="High", fix_state="wont-fix")

    result = evaluate([finding], DIGEST, [rule], [], [], NOW)

    assert result["summary"]["vexSuppressed"] == 1
    assert result["advisory"] == []


def _grype_report(fix: object) -> dict:
    vulnerability: dict[str, object] = {"id": PACKAGE.vulnerability_id, "severity": "High"}
    if fix is not None:
        vulnerability["fix"] = fix
    return {
        "matches": [
            {
                "vulnerability": vulnerability,
                "artifact": {
                    "name": PACKAGE.name,
                    "version": PACKAGE.version,
                    "purl": PACKAGE.purl,
                },
            }
        ]
    }


def test_fix_state_and_versions_are_read_from_grype(tmp_path: Path) -> None:
    path = tmp_path / "raw.json"
    _write_json(path, _grype_report({"state": "fixed", "versions": ["2.41-12+deb13u4"]}))

    [finding] = load_findings(path)

    assert finding.fix_state == "fixed"
    assert finding.fix_versions == ("2.41-12+deb13u4",)


@pytest.mark.parametrize("fix", [None, "wont-fix", {"state": 1}, {"versions": []}])
def test_malformed_or_missing_fix_blocks(tmp_path: Path, fix: object) -> None:
    path = tmp_path / "raw.json"
    _write_json(path, _grype_report(fix))

    result = evaluate(load_findings(path), DIGEST, [], [], [], NOW)

    assert result["gate"]["passed"] is False
    assert result["summary"]["remainingHigh"] == 1


def test_summary_lists_blocking_and_groups_advisory_findings() -> None:
    other = PackageKey("CVE-2026-5450", "libc-bin", "2.41-12+deb13u3", PURL + "-bin")
    findings = [
        Finding(key=PACKAGE, severity="High", fix_state="wont-fix"),
        Finding(key=other, severity="High", fix_state="wont-fix"),
        Finding(
            key=PackageKey("CVE-2026-1|x", "zlib1g", "1.3", "pkg:deb/debian/zlib1g@1.3"),
            severity="Critical",
            fix_state="fixed",
            fix_versions=("1.3.1",),
        ),
    ]

    summary = render_summary(evaluate(findings, DIGEST, [], [], [], NOW))

    assert "Gate: **BLOCKED**" in summary
    assert "High без исправления (не блокирует): 2" in summary
    # Значение из отчёта не ломает таблицу, а одна CVE сворачивается в строку.
    assert "| CVE-2026-1\\|x | Critical | zlib1g | 1.3 | fixed | 1.3.1 |" in summary
    assert "| CVE-2026-5450 | wont-fix | libc-bin 2.41-12+deb13u3, libc6 2.41-12+deb13u3 |" in summary


def test_main_warns_but_passes_on_unfixable_high_only(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = tmp_path / "raw.json"
    _write_json(report, _grype_report({"state": "wont-fix", "versions": []}))
    vex_dir = tmp_path / "vex"
    vex_dir.mkdir()
    waivers = tmp_path / "waivers.json"
    _write_json(waivers, {"schemaVersion": 1, "waivers": []})

    code = main(
        [
            "--report", str(report),
            "--image-digest", DIGEST,
            "--vex-dir", str(vex_dir),
            "--waivers", str(waivers),
            "--output", str(tmp_path / "policy.json"),
            "--summary", str(tmp_path / "summary.md"),
        ]
    )

    assert code == 0
    assert "::warning::" in capsys.readouterr().out
    assert "Gate: **PASS**" in (tmp_path / "summary.md").read_text(encoding="utf-8")


def test_medium_never_needs_an_exception() -> None:
    result = evaluate([_finding("Medium")], DIGEST, [], [], [], NOW)

    assert result["gate"]["passed"] is True
    assert result["remaining"] == []
