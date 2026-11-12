"""Runtime guard единственного FIPS VEX: метаданные Cloud Run, без исполнения image."""
from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from scripts.evaluate_image_scan import load_vex_rules
from scripts.probe_otel_candidate import require_unmodified_runtime
from scripts.probe_serving_fips import IMAGE, SERVICE, _describe, runtime_overrides, serving_revisions

REVIEWED_CHILD = "sha256:7faf8be3bd0a07dc0123d1bbfd58586d7fe909b3ebaca8f6f09d1a689c581d7c"


def guard(image_digest: str, vex_dir: Path) -> dict:
    rules = [rule for rule in load_vex_rules(vex_dir, datetime.now(UTC)) if rule.key.image_digest == image_digest and rule.key.package.vulnerability_id == "CVE-2026-119170"]
    if not rules:
        return {"imageDigest": image_digest, "required": False}
    if image_digest != REVIEWED_CHILD or len(rules) != 1 or rules[0].key.package.name != "python" or rules[0].key.package.version != "3.14.10" or rules[0].key.package.purl != "pkg:generic/python@3.14.10":
        raise ValueError("FIPS VEX is outside the reviewed exact image/package")
    service = _describe("services", SERVICE)
    require_unmodified_runtime(runtime_overrides({"spec": service["spec"]["template"]["spec"]}))
    checked = []
    for name in serving_revisions(service):
        revision = _describe("revisions", name)
        if revision["spec"]["containers"][0]["image"] == IMAGE + "@" + image_digest:
            require_unmodified_runtime(runtime_overrides(revision))
            checked.append(name)
    if not checked:
        raise ValueError("reviewed FIPS image is not in current serving targets")
    return {"imageDigest": image_digest, "required": True, "runtimeOverridesAbsent": True, "servingRevisions": checked}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--vex-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = guard(args.image_digest, args.vex_dir)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
