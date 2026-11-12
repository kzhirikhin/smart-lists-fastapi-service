"""Exact FIPS VEX теряет допуск при runtime drift; image не исполняется."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import fips_vex_guard as guard


def rule(digest=guard.REVIEWED_CHILD):
    return SimpleNamespace(key=SimpleNamespace(image_digest=digest, package=SimpleNamespace(vulnerability_id="CVE-2026-119170", name="python", version="3.14.10", purl="pkg:generic/python@3.14.10")))


def test_no_matching_vex_does_not_query_runtime(monkeypatch):
    monkeypatch.setattr(guard, "load_vex_rules", lambda *args: [])
    monkeypatch.setattr(guard, "_describe", lambda *args: pytest.fail("no matching VEX"))
    assert guard.guard(guard.REVIEWED_CHILD, Path("unused"))["required"] is False


@pytest.mark.parametrize("drift", ["none", "env", "mount", "command", "image"])
def test_runtime_drift_breaks_exact_vex(monkeypatch, drift):
    monkeypatch.setattr(guard, "load_vex_rules", lambda *args: [rule()])
    container = {"image": guard.IMAGE + "@" + guard.REVIEWED_CHILD}
    if drift == "env": container["env"] = [{"name": "OPENSSL_CONF", "value": "private"}]
    if drift == "mount": container["volumeMounts"] = [{"name": "private"}]
    if drift == "command": container["command"] = ["private"]
    if drift == "image": container["image"] = guard.IMAGE + "@sha256:" + "d" * 64
    def describe(kind, name):
        if kind == "services":
            return {"status": {"traffic": [{"revisionName": "insights-api-live", "percent": 100}]}, "spec": {"template": {"spec": {"containers": [{}]}}}}
        return {"spec": {"containers": [container]}}
    monkeypatch.setattr(guard, "_describe", describe)
    if drift == "none":
        assert guard.guard(guard.REVIEWED_CHILD, Path("unused"))["runtimeOverridesAbsent"] is True
    else:
        with pytest.raises(ValueError): guard.guard(guard.REVIEWED_CHILD, Path("unused"))


def test_same_cve_for_another_digest_requires_new_review(monkeypatch):
    digest = "sha256:" + "d" * 64
    monkeypatch.setattr(guard, "load_vex_rules", lambda *args: [rule(digest)])
    with pytest.raises(ValueError): guard.guard(digest, Path("unused"))


def test_scan_guard_precedes_policy_and_fails_closed():
    body = (Path(__file__).parents[1] / '.github/workflows/image-scan.yml').read_text()
    step = body.split('- name: Scan every serving digest', 1)[1].split('- name: Upload image scan reports', 1)[0]
    assert step.index('python -m scripts.fips_vex_guard') < step.index('python scripts/evaluate_image_scan.py')
    assert 'if ! python -m scripts.fips_vex_guard' in step
    assert 'Runtime conditions for exact FIPS VEX were not confirmed' in step
    assert 'continue-on-error' not in step
