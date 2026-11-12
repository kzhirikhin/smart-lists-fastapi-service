"""Границы ручной FIPS-диагностики: exact digest, sandbox и отсутствие секретов."""
import json
from types import SimpleNamespace

import pytest

from scripts import probe_serving_fips as probe

REF = probe.IMAGE + "@sha256:" + "a" * 64


def test_serving_includes_traffic_and_tagged_revisions():
    service = {"status": {"latestReadyRevisionName": "insights-api-latest", "traffic": [
        {"revisionName": "insights-api-live", "percent": 100},
        {"revisionName": "insights-api-tagged", "percent": 0, "tag": "preview"},
        {"revisionName": "insights-api-unused", "percent": 0},
        {"latestRevision": True, "tag": "latest"},
    ]}}
    assert probe.serving_revisions(service) == ["insights-api-latest", "insights-api-live", "insights-api-tagged"]


@pytest.mark.parametrize("service", [{}, {"status": {"traffic": [{"latestRevision": True, "percent": 100}]}}])
def test_missing_serving_target_fails_closed(service):
    with pytest.raises(ValueError):
        probe.serving_revisions(service)


@pytest.mark.parametrize("image", ["python:3.14", probe.IMAGE + ":latest", REF + ";bad", REF.replace(probe.PROJECT, "foreign")])
def test_mutable_or_foreign_images_are_rejected(image):
    with pytest.raises(ValueError):
        probe.probe_command(image)


def test_probe_has_no_network_mounts_credentials_or_root():
    command = probe.probe_command(REF)
    for control in ("--pull=never", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user=10001:10001", "--pids-limit=64", "--memory=128m", "--cpus=1"):
        assert control in command
    assert not any(arg in {"-v", "--mount", "-e", "--env", "--env-file", "--privileged"} for arg in command)
    assert command[-4:] == ["--entrypoint=python", REF, "-c", probe.PROBE]


def test_runtime_overrides_only_publish_names_and_flags():
    revision = {"spec": {"volumes": [{"secret": "private-volume"}], "containers": [{
        "env": [{"name": "OPENSSL_CONF", "value": "private-config"}, {"name": "CALLER", "value": "private-caller"}],
        "args": ["private-argument"],
    }]}}
    result = probe.runtime_overrides(revision)
    assert result == {"relevantEnvNames": ["OPENSSL_CONF"], "hasVolumes": True, "hasCommandOverride": True}
    assert "private" not in json.dumps(result)


def test_report_only_runs_validated_exact_image(monkeypatch):
    commands = []
    def run(command):
        commands.append(command)
        if command[0] == "gcloud":
            if command[2] == "services":
                return json.dumps({"status": {"traffic": [{"revisionName": "insights-api-live", "percent": 100}]}})
            return json.dumps({"spec": {"containers": [{"image": REF}]}})
        if command[1] == "pull":
            return ""
        return json.dumps({"python": "3.14.10", "openssl": "OpenSSL", "fipsMode": 0, "fipsProviderCount": 0})
    monkeypatch.setattr(probe, "_run", run)
    report = probe.collect_report()
    assert report["policyChanged"] is False
    assert report["revisions"][0]["image"] == REF
    assert ["docker", "pull", REF] in commands
    assert probe.probe_command(REF) in commands
    assert not any("deploy" in command for command in commands)


def test_sdk_failure_does_not_log_stderr(monkeypatch):
    monkeypatch.setattr(probe.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=1, stderr="private-token", stdout="private-config"))
    with pytest.raises(RuntimeError, match="gcloud failed with exit code 1") as error:
        probe._run(["gcloud", "run", "services", "describe"])
    assert "private" not in str(error.value)


@pytest.mark.parametrize("response", [
    {"python": "3.14.10", "openssl": "OpenSSL", "fipsMode": 0, "fipsProviderCount": 0, "unexpected": "private"},
    {"python": "3.14.10", "openssl": "OpenSSL", "fipsMode": "false", "fipsProviderCount": 0},
    {"python": "3.14.10", "openssl": "OpenSSL", "fipsMode": 0, "fipsProviderCount": -1},
])
def test_unexpected_probe_output_fails_closed(monkeypatch, response):
    monkeypatch.setattr(probe, "_describe", lambda kind, name: (
        {"status": {"traffic": [{"revisionName": "insights-api-live", "percent": 100}]}}
        if kind == "services" else {"spec": {"containers": [{"image": REF}]}}
    ))
    monkeypatch.setattr(probe, "_run", lambda command: json.dumps(response))
    with pytest.raises(ValueError, match="invalid FIPS probe response"):
        probe.collect_report()
