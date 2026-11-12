"""Проверка единственного подписанного candidate OpenTelemetry без изменения Cloud Run."""
from __future__ import annotations

import argparse
import json
import re
import tempfile
from pathlib import Path

from scripts.probe_serving_fips import (
    IMAGE, PROBE, _describe, _run, collect_report, probe_command, runtime_overrides,
)
from scripts.verify_attestation_certificate import verify_file

PARENT = "sha256:73784498e77809ea195a4f68753d93064f14fe9a3fbb6cb2933a9994fc087bba"
SOURCE_SHA = "5b6eb992beaa0d2c404bd5b687b900f29a4974e5"
REPOSITORY = "kzhirikhin/smart-lists-fastapi-service"
WORKFLOW = REPOSITORY + "/.github/workflows/deploy.yml"
CANDIDATE_PROBE = PROBE.replace("'python': sys.version.split()[0],", "'python': sys.version.split()[0], 'opentelemetryApi': __import__('importlib.metadata', fromlist=['version']).version('opentelemetry-api'),")


def validate_attestation(document: object) -> None:
    if not isinstance(document, list) or len(document) != 1:
        raise ValueError("expected one verified attestation")
    result = document[0]["verificationResult"]
    statement = result["statement"]
    if (
        statement.get("predicateType") != "https://slsa.dev/provenance/v1"
        or statement.get("subject") != [{"name": IMAGE, "digest": {"sha256": PARENT.removeprefix("sha256:")}}]
        or not result.get("verifiedTimestamps")
    ):
        raise ValueError("unexpected attestation subject or timestamp")
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "verification.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        verify_file(path, {"environment": "production", "event": "push", "runner": "github-hosted", "repository_id": "1199475908"})


def platform_digest(index: dict) -> str:
    if index.get("mediaType") != "application/vnd.oci.image.index.v1+json":
        raise ValueError("candidate is not an OCI index")
    matches = [m.get("digest") for m in index.get("manifests", []) if m.get("platform", {}).get("os") == "linux" and m.get("platform", {}).get("architecture") == "amd64"]
    if len(matches) != 1 or not isinstance(matches[0], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", matches[0]):
        raise ValueError("expected exactly one immutable linux/amd64 manifest")
    return matches[0]


def require_unmodified_runtime(overrides: dict) -> None:
    if overrides != {"relevantEnvNames": [], "hasVolumes": False, "hasCommandOverride": False}:
        raise ValueError("runtime overrides require a separate FIPS review")


def validate_probe(probe: dict) -> None:
    if (
        set(probe) != {"python", "openssl", "fipsMode", "fipsProviderCount", "opentelemetryApi"}
        or probe["python"] != "3.14.10"
        or probe["opentelemetryApi"] != "1.45.1"
        or type(probe["fipsMode"]) is not int or probe["fipsMode"] != 0
        or type(probe["fipsProviderCount"]) is not int or probe["fipsProviderCount"] != 0
        or not isinstance(probe["openssl"], str) or len(probe["openssl"]) > 200
    ):
        raise ValueError("candidate does not meet the reviewed package/FIPS conditions")


def candidate_report() -> tuple[dict, object]:
    parent_ref = IMAGE + "@" + PARENT
    verification = json.loads(_run([
        "gh", "attestation", "verify", "oci://" + parent_ref,
        "--repo", REPOSITORY, "--signer-workflow", WORKFLOW,
        "--signer-digest", SOURCE_SHA, "--source-ref", "refs/heads/main",
        "--source-digest", SOURCE_SHA, "--predicate-type", "https://slsa.dev/provenance/v1",
        "--deny-self-hosted-runners", "--format", "json",
    ]))
    validate_attestation(verification)
    index = json.loads(_run(["docker", "buildx", "imagetools", "inspect", parent_ref, "--raw"]))
    child = platform_digest(index)
    child_ref = IMAGE + "@" + child
    command = probe_command(child_ref)
    command[-1] = CANDIDATE_PROBE
    _run(["docker", "pull", child_ref])
    probe = json.loads(_run(command))
    validate_probe(probe)
    serving = collect_report()
    for entry in serving["revisions"]:
        require_unmodified_runtime(entry["runtimeOverrides"])
    service = _describe("services", "insights-api")
    template = runtime_overrides({"spec": service["spec"]["template"]["spec"]})
    require_unmodified_runtime(template)
    return {
        "schemaVersion": 1, "sourceSha": SOURCE_SHA,
        "parentImage": parent_ref, "image": child_ref,
        "attestationVerified": True, "probe": probe,
        "serviceTemplateOverrides": template, "serving": serving,
        "policyChanged": False,
    }, verification


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--verification-output", type=Path, required=True)
    args = parser.parse_args()
    report, verification = candidate_report()
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    args.verification_output.write_text(json.dumps(verification, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
