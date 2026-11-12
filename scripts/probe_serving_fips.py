"""Read-only диагностика cold Python в изолированной копии exact serving image.

Это не проба памяти работающего процесса и не VEX. Runtime overrides выводятся
только как имена/булевы признаки; значения env и конфигурация сервиса не публикуются.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

PROJECT = "project-5b7c1bd1-572b-410d-826"
REGION = "us-central1"
SERVICE = "insights-api"
IMAGE = f"us-central1-docker.pkg.dev/{PROJECT}/smart-lists/insights-api"
PROBE = """import _hashlib, json, ssl, sys
from pathlib import Path
print(json.dumps({
    'python': sys.version.split()[0],
    'openssl': ssl.OPENSSL_VERSION,
    'fipsMode': _hashlib.get_fips_mode(),
    'fipsProviderCount': sum(len(list(Path(p).rglob('fips.so'))) for p in ('/usr/lib', '/usr/local/lib')),
}))
"""


def _run(command: list[str]) -> str:
    result = subprocess.run(command, capture_output=True, text=True, timeout=180)
    if result.returncode:
        # stderr SDK может содержать конфигурацию или credentials.
        raise RuntimeError(f"{command[0]} failed with exit code {result.returncode}")
    return result.stdout


def _describe(kind: str, name: str) -> dict:
    return json.loads(_run([
        "gcloud", "run", kind, "describe", name, "--project", PROJECT,
        "--region", REGION, "--format=json",
    ]))


def serving_revisions(service: dict) -> list[str]:
    status = service.get("status", {})
    names = set()
    for target in status.get("traffic", []):
        if target.get("percent", 0) > 0 or target.get("tag"):
            name = target.get("revisionName")
            if not name and target.get("latestRevision"):
                name = status.get("latestReadyRevisionName")
            if not isinstance(name, str) or not re.fullmatch(r"insights-api-[a-z0-9-]+", name):
                raise ValueError("unresolved serving revision")
            names.add(name)
    if not names:
        raise ValueError("no serving revisions")
    return sorted(names)


def runtime_overrides(revision: dict) -> dict:
    spec = revision.get("spec", {})
    containers = spec.get("containers", [])
    if len(containers) != 1:
        raise ValueError("expected one application container")
    container = containers[0]
    names = sorted({
        entry["name"] for entry in container.get("env", [])
        if isinstance(entry.get("name"), str)
        and re.search(r"FIPS|OPENSSL|^LD_|^PYTHON(PATH|HOME)$", entry["name"], re.I)
    })
    return {
        "relevantEnvNames": names,
        "hasVolumes": bool(spec.get("volumes") or container.get("volumeMounts")),
        "hasCommandOverride": bool(container.get("command") or container.get("args")),
    }


def probe_command(image: str) -> list[str]:
    if not re.fullmatch(re.escape(IMAGE) + r"@sha256:[0-9a-f]{64}", image):
        raise ValueError("unexpected mutable or foreign image reference")
    return [
        "docker", "run", "--rm", "--pull=never", "--network=none", "--read-only",
        "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=64",
        "--memory=128m", "--cpus=1", "--user=10001:10001", "--entrypoint=python",
        image, "-c", PROBE,
    ]


def collect_report() -> dict:
    entries = []
    for name in serving_revisions(_describe("services", SERVICE)):
        revision = _describe("revisions", name)
        overrides = runtime_overrides(revision)
        image = revision["spec"]["containers"][0]["image"]
        command = probe_command(image)
        _run(["docker", "pull", image])
        probe = json.loads(_run(command))
        if (
            not isinstance(probe, dict)
            or set(probe) != {"python", "openssl", "fipsMode", "fipsProviderCount"}
            or type(probe["fipsMode"]) is not int
            or probe["fipsMode"] not in (0, 1)
            or type(probe["fipsProviderCount"]) is not int
            or probe["fipsProviderCount"] < 0
            or any(not isinstance(probe[key], str) or len(probe[key]) > 200 for key in ("python", "openssl"))
        ):
            raise ValueError("invalid FIPS probe response")
        entries.append({"revision": name, "image": image, "runtimeOverrides": overrides, "coldPythonProbe": probe})
    return {
        "schemaVersion": 1,
        "scope": "isolated exact image; selected runtime overrides; not live process memory or a VEX",
        "policyChanged": False,
        "revisions": entries,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(json.dumps(collect_report(), indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
