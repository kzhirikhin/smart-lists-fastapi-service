"""Одноразовый promotion проверенного OpenTelemetry image; обычный deploy gate не меняется."""
from __future__ import annotations

import argparse
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scripts import probe_otel_candidate as candidate
from scripts.evaluate_image_scan import main as evaluate_policy
from scripts.fips_vex_guard import REVIEWED_CHILD
from scripts.probe_serving_fips import IMAGE, PROJECT, REGION, SERVICE, _describe, _run, runtime_overrides, serving_revisions

BASELINE = "sha256:534fcd9b6d813f37a9307e1706302d79d1215abbb6a449a59c74da27d802e870"
RUNTIME_SA = "insights-api-runtime@" + PROJECT + ".iam.gserviceaccount.com"
ROOT = Path(__file__).resolve().parents[1]
RECORD = ROOT / "security/promotions/otel-1.45.1.json"


def load_record(path: Path, now: datetime) -> dict:
    record = json.loads(path.read_text(encoding="utf-8"))
    required = {"schemaVersion", "parentDigest", "imageDigest", "sourceSha", "baselineDigest", "reviewedAt", "expiresAt", "approval"}
    if not isinstance(record, dict) or set(record) != required or record["schemaVersion"] != 1:
        raise ValueError("invalid promotion record")
    if record["parentDigest"] != candidate.PARENT or record["sourceSha"] != candidate.SOURCE_SHA or record["baselineDigest"] != BASELINE:
        raise ValueError("unreviewed candidate source or baseline")
    if record["imageDigest"] != REVIEWED_CHILD:
        raise ValueError("invalid platform digest")
    if not isinstance(record["approval"], str) or not re.fullmatch(r"https://github.com/kzhirikhin/smart-lists-fastapi-service/pull/[1-9][0-9]*", record["approval"]):
        raise ValueError("missing review PR")
    reviewed = datetime.fromisoformat(record["reviewedAt"].replace("Z", "+00:00"))
    expires = datetime.fromisoformat(record["expiresAt"].replace("Z", "+00:00"))
    if reviewed.tzinfo is None or expires.tzinfo is None or not reviewed < expires <= reviewed + timedelta(days=7) or reviewed > now + timedelta(minutes=5) or now >= expires:
        raise ValueError("expired or invalid promotion review window")
    return record


def validate_review_binding(record: dict, vex_dir: Path) -> None:
    document = json.loads((vex_dir / (record["imageDigest"].removeprefix("sha256:") + ".cdx.json")).read_text(encoding="utf-8"))
    properties = document["metadata"]["properties"]
    for name, expected in (("smart-lists:vex:approval", record["approval"]), ("smart-lists:vex:reviewed-at", record["reviewedAt"])):
        if [item.get("value") for item in properties if item.get("name") == name] != [expected]:
            raise ValueError("promotion record and exact VEX have different review metadata")


def validate_report(report: dict, record: dict) -> None:
    if report["parentImage"] != IMAGE + "@" + record["parentDigest"] or report["image"] != IMAGE + "@" + record["imageDigest"] or report["sourceSha"] != record["sourceSha"] or report["attestationVerified"] is not True:
        raise ValueError("candidate differs from reviewed record")
    candidate.validate_probe(report["probe"])
    candidate.require_unmodified_runtime(report["serviceTemplateOverrides"])
    entries = report["serving"]["revisions"]
    if not entries:
        raise ValueError("no serving baseline")
    for entry in entries:
        candidate.require_unmodified_runtime(entry["runtimeOverrides"])
        if entry["image"] not in {IMAGE + "@" + BASELINE, report["image"]}:
            raise ValueError("serving changed since review; refuse rollback")


def validate_policy(result: dict, record: dict) -> None:
    summary = result["summary"]
    if result["imageDigest"] != record["imageDigest"] or result["gate"]["passed"] is not True or summary["remainingCritical"] != 0 or summary["remainingHigh"] != 0 or summary["vexSuppressed"] != 1 or summary["waiverSuppressed"] != 0 or len(result["suppressed"]) != 1:
        raise ValueError("promotion requires a passing exact policy with one VEX and no waiver")
    item = result["suppressed"][0]
    if any(item.get(key) != value for key, value in {
        "vulnerabilityId": "CVE-2026-119170", "packageName": "python", "packageVersion": "3.14.10",
        "purl": "pkg:generic/python@3.14.10", "mechanism": "vex_not_affected",
    }.items()):
        raise ValueError("promotion exception is not the reviewed Python FIPS finding")


def verify_sbom() -> None:
    attachment = json.loads(_run([
        "gcloud", "artifacts", "attachments", "describe", "cyclonedx-" + candidate.PARENT.removeprefix("sha256:")[:48],
        "--project", PROJECT, "--location", REGION, "--repository", "smart-lists", "--format=json",
    ]))
    target = f"projects/{PROJECT}/locations/{REGION}/repositories/smart-lists/packages/insights-api/versions/{candidate.PARENT}"
    if attachment.get("target") != target or attachment.get("type") != "application/vnd.cyclonedx+json" or attachment.get("attachmentNamespace") != "anchore.com/syft" or not isinstance(attachment.get("files"), list) or len(attachment["files"]) != 1:
        raise ValueError("candidate lacks the expected exact SBOM attachment")


def check_current_runtime(record: dict) -> list[tuple[str, str]]:
    service = _describe("services", SERVICE)
    candidate.require_unmodified_runtime(runtime_overrides({"spec": service["spec"]["template"]["spec"]}))
    targets = []
    for name in serving_revisions(service):
        revision = _describe("revisions", name)
        candidate.require_unmodified_runtime(runtime_overrides(revision))
        image = revision["spec"]["containers"][0]["image"]
        if image not in {IMAGE + "@" + BASELINE, IMAGE + "@" + record["imageDigest"]}:
            raise ValueError("serving baseline changed before promotion")
        targets.append((name, image))
    return targets


def promote(record_path: Path, output: Path) -> dict:
    record = load_record(record_path, datetime.now(UTC))
    validate_review_binding(record, ROOT / "security/vex")
    output.mkdir(parents=True, exist_ok=True)
    report, verification = candidate.candidate_report()
    validate_report(report, record)
    (output / "candidate.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (output / "verification.json").write_text(json.dumps(verification, indent=2) + "\n", encoding="utf-8")
    verify_sbom()
    raw, policy, summary = output / "grype.json", output / "policy.json", output / "summary.md"
    _run(["grype", report["image"], "-o", "json", "--file", str(raw)])
    code = evaluate_policy([
        "--report", str(raw), "--image-digest", record["imageDigest"],
        "--vex-dir", str(ROOT / "security/vex"), "--waivers", str(ROOT / "security/waivers.json"),
        "--output", str(policy), "--summary", str(summary),
    ])
    if code != 0:
        raise ValueError("fresh exact-image policy blocked promotion")
    result = json.loads(policy.read_text(encoding="utf-8"))
    validate_policy(result, record)
    # Повторная проверка времени и runtime непосредственно перед мутацией.
    load_record(record_path, datetime.now(UTC))
    current = check_current_runtime(record)
    if any(image != report["image"] for _, image in current):
        _run([
            "gcloud", "run", "deploy", SERVICE, "--project", PROJECT, "--region", REGION,
            "--image", report["parentImage"], "--service-account", RUNTIME_SA,
            "--port", "8000", "--quiet",
        ])
    final = check_current_runtime(record)
    if any(image != report["image"] for _, image in final):
        raise ValueError("post-deploy serving digest does not match reviewed child")
    promotion = {"sourceSha": record["sourceSha"], "parentImage": report["parentImage"], "image": report["image"], "servingRevisions": [name for name, _ in final], "policySummary": result["summary"], "review": record["approval"]}
    (output / "promotion.json").write_text(json.dumps(promotion, indent=2) + "\n", encoding="utf-8")
    return promotion


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(promote(RECORD, args.output_dir), indent=2))


if __name__ == "__main__":
    main()
