"""Контракты exact candidate: подпись, platform link, пакеты/FIPS и runtime overrides."""
import copy
import json

import pytest

from scripts import probe_otel_candidate as candidate

CHILD = "sha256:" + "c" * 64
INDEX = {"mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [{"digest": CHILD, "platform": {"os": "linux", "architecture": "amd64"}}]}
PROBE = {"python": "3.14.10", "opentelemetryApi": "1.45.1", "openssl": "OpenSSL 3.5.7", "fipsMode": 0, "fipsProviderCount": 0}
EMPTY = {"relevantEnvNames": [], "hasVolumes": False, "hasCommandOverride": False}


def attestation():
    return [{"verificationResult": {"statement": {
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [{"name": candidate.IMAGE, "digest": {"sha256": candidate.PARENT.removeprefix("sha256:")}}],
    }, "verifiedTimestamps": [{"timestamp": "2026-11-12T08:14:00Z"}]}}]


def test_platform_link_requires_exactly_one_amd64_child():
    assert candidate.platform_digest(INDEX) == CHILD
    for bad in ({}, {**INDEX, "manifests": []}, {**INDEX, "manifests": INDEX["manifests"] * 2}, {**INDEX, "manifests": [{"digest": ":latest", "platform": {"os": "linux", "architecture": "amd64"}}]}):
        with pytest.raises(ValueError):
            candidate.platform_digest(bad)


@pytest.mark.parametrize("field,value", [("python", "3.14.9"), ("opentelemetryApi", "1.45.0"), ("fipsMode", 1), ("fipsMode", False), ("fipsProviderCount", 1), ("unexpected", "private")])
def test_unreviewed_probe_fails_closed(field, value):
    with pytest.raises(ValueError):
        candidate.validate_probe({**PROBE, field: value})


@pytest.mark.parametrize("overrides", [{}, {**EMPTY, "relevantEnvNames": ["OPENSSL_CONF"]}, {**EMPTY, "hasVolumes": True}, {**EMPTY, "hasCommandOverride": True}])
def test_runtime_drift_requires_new_review(overrides):
    with pytest.raises(ValueError):
        candidate.require_unmodified_runtime(overrides)


def test_wrong_subject_cannot_reach_certificate_acceptance(monkeypatch):
    document = attestation()
    document[0]["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] = "d" * 64
    monkeypatch.setattr(candidate, "verify_file", lambda *args: pytest.fail("must reject subject first"))
    with pytest.raises(ValueError):
        candidate.validate_attestation(document)


def test_valid_subject_also_requires_signed_certificate_claims(monkeypatch):
    seen = []
    monkeypatch.setattr(candidate, "verify_file", lambda path, expected: seen.append((json.loads(path.read_text()), expected)))
    candidate.validate_attestation(attestation())
    assert seen[0][1] == {"environment": "production", "event": "push", "runner": "github-hosted", "repository_id": "1199475908"}


def test_candidate_signature_is_checked_before_pull_and_probe(monkeypatch):
    commands = []
    def run(command):
        commands.append(command)
        if command[0] == "gh":
            return json.dumps(attestation())
        if "imagetools" in command:
            return json.dumps(INDEX)
        if command[1] == "pull":
            return ""
        return json.dumps(PROBE)
    monkeypatch.setattr(candidate, "_run", run)
    monkeypatch.setattr(candidate, "verify_file", lambda *args: None)
    monkeypatch.setattr(candidate, "collect_report", lambda: {"revisions": [{"runtimeOverrides": copy.deepcopy(EMPTY)}]})
    monkeypatch.setattr(candidate, "_describe", lambda *args: {"spec": {"template": {"spec": {"containers": [{}]}}}})
    report, verification = candidate.candidate_report()
    assert report["policyChanged"] is False
    assert report["image"] == candidate.IMAGE + "@" + CHILD
    assert report["sourceSha"] == candidate.SOURCE_SHA
    assert commands[0][0] == "gh"
    for argument in ("--signer-workflow", "--signer-digest", "--source-digest", "--source-ref", "--deny-self-hosted-runners"):
        assert argument in commands[0]
    assert commands[0].count(candidate.SOURCE_SHA) == 2
    assert "--network=none" in commands[-1]
    assert not any("deploy" in command for command in commands)
