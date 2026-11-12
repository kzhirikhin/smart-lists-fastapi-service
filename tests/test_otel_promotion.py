"""Мутация разрешена только после всех exact review/provenance/FIPS/policy guards."""
import copy
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from scripts import promote_reviewed_otel as promotion

NOW = datetime(2026, 11, 12, 9, tzinfo=UTC)


def record():
    return {"schemaVersion": 1, "parentDigest": promotion.candidate.PARENT, "imageDigest": promotion.REVIEWED_CHILD, "sourceSha": promotion.candidate.SOURCE_SHA, "baselineDigest": promotion.BASELINE, "reviewedAt": "2026-11-12T00:00:00Z", "expiresAt": "2026-11-18T00:00:00Z", "approval": "https://github.com/kzhirikhin/smart-lists-fastapi-service/pull/107"}


def policy():
    return {"imageDigest": promotion.REVIEWED_CHILD, "gate": {"passed": True}, "summary": {"remainingCritical": 0, "remainingHigh": 0, "vexSuppressed": 1, "waiverSuppressed": 0}, "suppressed": [{"vulnerabilityId": "CVE-2026-119170", "packageName": "python", "packageVersion": "3.14.10", "purl": "pkg:generic/python@3.14.10", "mechanism": "vex_not_affected"}]}


def report():
    return {"parentImage": promotion.IMAGE + "@" + promotion.candidate.PARENT, "image": promotion.IMAGE + "@" + promotion.REVIEWED_CHILD, "sourceSha": promotion.candidate.SOURCE_SHA, "attestationVerified": True, "probe": {"python": "3.14.10", "openssl": "OpenSSL", "opentelemetryApi": "1.45.1", "fipsMode": 0, "fipsProviderCount": 0}, "serviceTemplateOverrides": {"relevantEnvNames": [], "hasVolumes": False, "hasCommandOverride": False}, "serving": {"revisions": [{"image": promotion.IMAGE + "@" + promotion.BASELINE, "runtimeOverrides": {"relevantEnvNames": [], "hasVolumes": False, "hasCommandOverride": False}}]}}


@pytest.mark.parametrize("field,value", [("parentDigest", "sha256:" + "d" * 64), ("imageDigest", "sha256:" + "d" * 64), ("sourceSha", "d" * 40), ("baselineDigest", "sha256:" + "d" * 64), ("expiresAt", "2026-12-12T00:00:00Z"), ("expiresAt", "2026-11-12T01:00:00Z"), ("reviewedAt", "2026-11-13T00:00:00Z"), ("approval", "https://example.com/approved")])
def test_unreviewed_or_stale_record_blocks(field, value, tmp_path):
    path = tmp_path / "review.json"
    path.write_text(json.dumps({**record(), field: value}))
    with pytest.raises(ValueError):
        promotion.load_record(path, NOW)


def test_record_and_vex_must_reference_same_review(tmp_path):
    path = tmp_path / (promotion.REVIEWED_CHILD.removeprefix("sha256:") + ".cdx.json")
    path.write_text(json.dumps({"metadata": {"properties": [{"name": "smart-lists:vex:approval", "value": record()["approval"]}, {"name": "smart-lists:vex:reviewed-at", "value": record()["reviewedAt"]}]}}))
    promotion.validate_review_binding(record(), tmp_path)
    bad = record(); bad["approval"] += "1"
    with pytest.raises(ValueError):
        promotion.validate_review_binding(bad, tmp_path)


@pytest.mark.parametrize("change", ["digest", "gate", "critical", "high", "waiver", "extra-vex", "other-cve"])
def test_any_other_blocker_or_suppression_blocks(change):
    result = policy()
    if change == "digest": result["imageDigest"] = "sha256:" + "d" * 64
    elif change == "gate": result["gate"]["passed"] = False
    elif change == "critical": result["summary"]["remainingCritical"] = 1
    elif change == "high": result["summary"]["remainingHigh"] = 1
    elif change == "waiver": result["summary"]["waiverSuppressed"] = 1
    elif change == "extra-vex": result["suppressed"].append(copy.deepcopy(result["suppressed"][0]))
    else: result["suppressed"][0]["vulnerabilityId"] = "CVE-2026-999999"
    with pytest.raises(ValueError):
        promotion.validate_policy(result, record())


@pytest.fixture
def execution(monkeypatch, tmp_path):
    events = []
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW
    monkeypatch.setattr(promotion, "datetime", Clock)
    path = tmp_path / "review.json"; path.write_text(json.dumps(record()))
    monkeypatch.setattr(promotion, "validate_review_binding", lambda *args: events.append("review"))
    monkeypatch.setattr(promotion.candidate, "candidate_report", lambda: (events.append("candidate") or report(), {}))
    monkeypatch.setattr(promotion, "verify_sbom", lambda: events.append("sbom"))
    monkeypatch.setattr(promotion, "_run", lambda command: events.append(command) or "")
    def evaluate(arguments):
        events.append("policy")
        Path(arguments[arguments.index("--output") + 1]).write_text(json.dumps(policy()))
        return 0
    monkeypatch.setattr(promotion, "evaluate_policy", evaluate)
    states = iter([[('old', promotion.IMAGE + '@' + promotion.BASELINE)], [('new', promotion.IMAGE + '@' + promotion.REVIEWED_CHILD)]])
    monkeypatch.setattr(promotion, "check_current_runtime", lambda record: next(states))
    return path, tmp_path / "output", events


def test_mutation_runs_only_after_signature_sbom_and_passing_policy(execution):
    path, output, events = execution
    result = promotion.promote(path, output)
    deploys = [event for event in events if isinstance(event, list) and event[:3] == ["gcloud", "run", "deploy"]]
    assert len(deploys) == 1
    assert events.index("review") < events.index("candidate") < events.index("sbom") < events.index("policy") < events.index(deploys[0])
    assert promotion.IMAGE + '@' + promotion.candidate.PARENT in deploys[0]
    assert result["servingRevisions"] == ["new"]


def test_failed_fresh_policy_cannot_reach_deploy(execution, monkeypatch):
    path, output, events = execution
    monkeypatch.setattr(promotion, "evaluate_policy", lambda args: 1)
    with pytest.raises(ValueError, match="policy blocked"):
        promotion.promote(path, output)
    assert not any(isinstance(event, list) and "deploy" in event for event in events)


def test_runtime_drift_cannot_reach_deploy(execution, monkeypatch):
    path, output, events = execution
    def refuse(record):
        raise ValueError("runtime changed")
    monkeypatch.setattr(promotion, "check_current_runtime", refuse)
    with pytest.raises(ValueError, match="runtime changed"):
        promotion.promote(path, output)
    assert not any(isinstance(event, list) and "deploy" in event for event in events)


def test_workflow_is_manual_main_production_and_tests_gate_it():
    body = (promotion.ROOT / '.github/workflows/promote-reviewed-otel.yml').read_text()
    assert "workflow_dispatch:" in body and "  push:" not in body
    assert "github.ref == 'refs/heads/main'" in body
    assert "needs: test" in body and "environment: production" in body
    assert "inputs:" not in body
    assert "continue-on-error" not in body
    assert "GRYPE_DB_REQUIRE_UPDATE_CHECK: 'true'" in body


@pytest.mark.parametrize("bad", ["target", "type", "files"])
def test_sbom_attachment_must_match_exact_candidate(monkeypatch, bad):
    attachment = {"target": f"projects/{promotion.PROJECT}/locations/{promotion.REGION}/repositories/smart-lists/packages/insights-api/versions/{promotion.candidate.PARENT}", "type": "application/vnd.cyclonedx+json", "attachmentNamespace": "anchore.com/syft", "files": [{}]}
    monkeypatch.setattr(promotion, "_run", lambda command: json.dumps(attachment))
    promotion.verify_sbom()
    attachment[bad] = [] if bad == "files" else "wrong"
    with pytest.raises(ValueError, match="SBOM"):
        promotion.verify_sbom()


def test_review_expiring_during_scan_cannot_reach_deploy(execution, monkeypatch):
    path, output, events = execution
    original = promotion.load_record
    calls = 0
    def load(path, now):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise ValueError("expired during scan")
        return original(path, now)
    monkeypatch.setattr(promotion, "load_record", load)
    with pytest.raises(ValueError, match="expired during scan"):
        promotion.promote(path, output)
    assert not any(isinstance(event, list) and "deploy" in event for event in events)


@pytest.mark.parametrize("field,value", [("image", promotion.IMAGE + '@sha256:' + 'd' * 64), ("sourceSha", 'd' * 40), ("attestationVerified", False)])
def test_candidate_report_drift_blocks(field, value):
    with pytest.raises(ValueError):
        promotion.validate_report({**report(), field: value}, record())


def test_plain_run_scalars_do_not_contain_yaml_mapping_delimiter():
    # Узкий regression guard известной формы, не общий YAML parser.
    # В plain scalar shell quotes не экранируют YAML-разделитель ": ".
    for path in sorted((promotion.ROOT / '.github/workflows').glob('*.yml')):
        for line in path.read_text().splitlines():
            stripped = line.strip()
            if not stripped.startswith('run: '):
                continue
            scalar = stripped.removeprefix('run: ').strip()
            if scalar and scalar[0] not in ('|', '>', chr(34), chr(39)):
                assert ': ' not in scalar, str(path)
