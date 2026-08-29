"""Строгая оценка Grype-отчёта с CycloneDX VEX и временными waiver."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse
from uuid import UUID


BLOCKING_SEVERITIES = {"High", "Critical"}
CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
WAIVER_ID = re.compile(r"^WAIVER-\d{4}-\d{3,}$")
ACTOR = re.compile(r"^@[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
APPROVAL_URL = re.compile(
    r"^https://github\.com/kzhirikhin/smart-lists-fastapi-service/pull/[1-9]\d*$"
)
# `?` является штатным разделителем qualifiers в purl. Сопоставление ниже в
# любом случае использует точное равенство, а не glob; звёздочку запрещаем ещё
# и на входе, чтобы автор политики не мог принять её за поддерживаемый wildcard.
WILDCARDS = frozenset("*")
MAX_WAIVER_LIFETIME = timedelta(days=30)
FUTURE_CLOCK_SKEW = timedelta(minutes=5)

CYCLONEDX_SCHEMA = "https://cyclonedx.org/schema/bom-1.6.schema.json"
VEX_PROPERTY_PREFIX = "smart-lists:vex:"
VEX_JUSTIFICATIONS = {
    "code_not_present",
    "code_not_reachable",
    "requires_configuration",
    "requires_dependency",
    "requires_environment",
    "protected_by_compiler",
    "protected_at_runtime",
    "protected_at_perimeter",
    "protected_by_mitigating_control",
}


class PolicyError(ValueError):
    """Политика не может быть безопасно применена."""


@dataclass(frozen=True)
class PackageKey:
    vulnerability_id: str
    name: str
    version: str
    purl: str


@dataclass(frozen=True)
class PolicyKey:
    image_digest: str
    package: PackageKey


@dataclass(frozen=True)
class Rule:
    key: PolicyKey
    mechanism: str
    rule_id: str
    expires_at: datetime | None = None


@dataclass(frozen=True)
class Finding:
    key: PackageKey
    severity: str


def _read_json(path: Path, context: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"{context}: не удалось прочитать JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise PolicyError(f"{context}: корнем JSON должен быть объект")
    return value


def _object(value: object, context: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise PolicyError(f"{context}: ожидается объект")
    return value


def _array(value: object, context: str) -> list[object]:
    if not isinstance(value, list):
        raise PolicyError(f"{context}: ожидается массив")
    return value


def _string(
    value: object,
    context: str,
    *,
    min_length: int = 1,
) -> str:
    if not isinstance(value, str) or len(value.strip()) < min_length:
        raise PolicyError(
            f"{context}: ожидается непустая строка длиной не менее {min_length}"
        )
    return value.strip()


def _timestamp(value: object, context: str) -> datetime:
    raw = _string(value, context)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PolicyError(f"{context}: требуется ISO 8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise PolicyError(f"{context}: timezone обязателен")
    return parsed.astimezone(UTC)


def _https_url(value: object, context: str) -> str:
    raw = _string(value, context)
    parsed = urlparse(raw)
    if parsed.scheme != "https" or not parsed.netloc:
        raise PolicyError(f"{context}: требуется абсолютный HTTPS URL")
    return raw


def _approval_url(value: object, context: str) -> str:
    raw = _https_url(value, context)
    if not APPROVAL_URL.fullmatch(raw):
        raise PolicyError(f"{context}: требуется URL PR этого репозитория")
    return raw


def _exact(value: object, context: str) -> str:
    raw = _string(value, context)
    if any(char in raw for char in WILDCARDS):
        raise PolicyError(f"{context}: wildcard запрещён")
    return raw


def _digest(value: object, context: str) -> str:
    raw = _exact(value, context)
    if not DIGEST.fullmatch(raw):
        raise PolicyError(f"{context}: требуется sha256:<64 lowercase hex>")
    return raw


def _cve(value: object, context: str) -> str:
    raw = _exact(value, context)
    if not CVE.fullmatch(raw):
        raise PolicyError(f"{context}: подавлять можно только точный CVE-id")
    return raw


def _properties(value: object, context: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for index, item in enumerate(_array(value, context)):
        prop = _object(item, f"{context}[{index}]")
        name = _string(prop.get("name"), f"{context}[{index}].name")
        prop_value = _string(prop.get("value"), f"{context}[{index}].value")
        result.setdefault(name, []).append(prop_value)
    return result


def _one_property(
    properties: dict[str, list[str]], name: str, context: str
) -> str:
    values = properties.get(name, [])
    if len(values) != 1:
        raise PolicyError(f"{context}: свойство {name!r} должно встретиться ровно раз")
    return values[0]


def _package_key(
    vulnerability_id: object,
    package: dict[str, object],
    context: str,
) -> PackageKey:
    name = _exact(package.get("name"), f"{context}.name")
    version = _exact(package.get("version"), f"{context}.version")
    purl = _exact(package.get("purl"), f"{context}.purl")
    if not purl.startswith("pkg:") or "@" not in purl:
        raise PolicyError(f"{context}.purl: требуется versioned Package URL")
    return PackageKey(
        vulnerability_id=_cve(vulnerability_id, f"{context}.vulnerabilityId"),
        name=name,
        version=version,
        purl=purl,
    )


def _actor(value: object, context: str) -> str:
    raw = _exact(value, context)
    if not ACTOR.fullmatch(raw):
        raise PolicyError(f"{context}: требуется GitHub actor в виде @login")
    return raw


def _uuid_serial(value: object, context: str) -> str:
    raw = _string(value, context)
    if not raw.startswith("urn:uuid:"):
        raise PolicyError(f"{context}: требуется urn:uuid:<UUID>")
    try:
        UUID(raw.removeprefix("urn:uuid:"))
    except ValueError as exc:
        raise PolicyError(f"{context}: некорректный UUID") from exc
    return raw


def load_findings(report_path: Path) -> list[Finding]:
    report = _read_json(report_path, str(report_path))
    matches = _array(report.get("matches"), f"{report_path}.matches")
    findings: list[Finding] = []
    for index, item in enumerate(matches):
        context = f"{report_path}.matches[{index}]"
        match = _object(item, context)
        vulnerability = _object(match.get("vulnerability"), f"{context}.vulnerability")
        artifact = _object(match.get("artifact"), f"{context}.artifact")
        vulnerability_id = _string(
            vulnerability.get("id"), f"{context}.vulnerability.id"
        )
        severity = _string(
            vulnerability.get("severity"), f"{context}.vulnerability.severity"
        )
        name = _string(artifact.get("name"), f"{context}.artifact.name")
        version = _string(artifact.get("version"), f"{context}.artifact.version")
        # Без точного purl находка остаётся блокирующей: исключение к ней
        # безопасно привязать невозможно.
        purl_value = artifact.get("purl")
        purl = purl_value.strip() if isinstance(purl_value, str) else ""
        findings.append(
            Finding(
                key=PackageKey(vulnerability_id, name, version, purl),
                severity=severity,
            )
        )
    return findings


def load_vex_rules(vex_dir: Path, now: datetime) -> list[Rule]:
    if not vex_dir.is_dir():
        raise PolicyError(f"{vex_dir}: каталог VEX отсутствует")

    rules: list[Rule] = []
    seen: set[PolicyKey] = set()
    for path in sorted(vex_dir.glob("*.cdx.json")):
        context = str(path)
        document = _read_json(path, context)
        if document.get("$schema") != CYCLONEDX_SCHEMA:
            raise PolicyError(f"{context}: разрешена только схема CycloneDX 1.6")
        if document.get("bomFormat") != "CycloneDX" or document.get(
            "specVersion"
        ) != "1.6":
            raise PolicyError(f"{context}: требуется CycloneDX JSON 1.6")
        serial = _uuid_serial(document.get("serialNumber"), f"{context}.serialNumber")
        if not isinstance(document.get("version"), int) or document["version"] < 1:
            raise PolicyError(f"{context}.version: требуется положительное целое")

        metadata = _object(document.get("metadata"), f"{context}.metadata")
        _timestamp(metadata.get("timestamp"), f"{context}.metadata.timestamp")
        product = _object(metadata.get("component"), f"{context}.metadata.component")
        if product.get("type") != "container" or product.get("name") != "insights-api":
            raise PolicyError(
                f"{context}.metadata.component: ожидается container insights-api"
            )
        image_digest = _digest(
            product.get("version"), f"{context}.metadata.component.version"
        )
        if path.name != f"{image_digest.removeprefix('sha256:')}.cdx.json":
            raise PolicyError(f"{context}: имя файла должно совпадать с image digest")
        product_ref = _exact(
            product.get("bom-ref"), f"{context}.metadata.component.bom-ref"
        )
        if image_digest not in product_ref:
            raise PolicyError(f"{context}: product bom-ref не содержит image digest")

        metadata_properties = _properties(
            metadata.get("properties"), f"{context}.metadata.properties"
        )
        reviewer = _one_property(
            metadata_properties,
            f"{VEX_PROPERTY_PREFIX}reviewed-by",
            f"{context}.metadata.properties",
        )
        _actor(reviewer, f"{context}.metadata.reviewed-by")
        reviewed_at = _timestamp(
            _one_property(
                metadata_properties,
                f"{VEX_PROPERTY_PREFIX}reviewed-at",
                f"{context}.metadata.properties",
            ),
            f"{context}.metadata.reviewed-at",
        )
        if reviewed_at > now + FUTURE_CLOCK_SKEW:
            raise PolicyError(f"{context}: review не может быть из будущего")
        _approval_url(
            _one_property(
                metadata_properties,
                f"{VEX_PROPERTY_PREFIX}approval",
                f"{context}.metadata.properties",
            ),
            f"{context}.metadata.approval",
        )

        components: dict[str, dict[str, object]] = {}
        for index, item in enumerate(
            _array(document.get("components"), f"{context}.components")
        ):
            component = _object(item, f"{context}.components[{index}]")
            ref = _exact(
                component.get("bom-ref"), f"{context}.components[{index}].bom-ref"
            )
            if ref in components:
                raise PolicyError(f"{context}: повторный component bom-ref {ref!r}")
            components[ref] = component

        vulnerabilities = _array(
            document.get("vulnerabilities"), f"{context}.vulnerabilities"
        )
        if not vulnerabilities:
            raise PolicyError(f"{context}: VEX без vulnerability statements запрещён")
        for index, item in enumerate(vulnerabilities):
            vuln_context = f"{context}.vulnerabilities[{index}]"
            vulnerability = _object(item, vuln_context)
            vulnerability_id = _cve(
                vulnerability.get("id"), f"{vuln_context}.id"
            )
            analysis = _object(
                vulnerability.get("analysis"), f"{vuln_context}.analysis"
            )
            if analysis.get("state") != "not_affected":
                raise PolicyError(
                    f"{vuln_context}: только not_affected может подавлять находку"
                )
            justification = _string(
                analysis.get("justification"), f"{vuln_context}.analysis.justification"
            )
            if justification not in VEX_JUSTIFICATIONS:
                raise PolicyError(
                    f"{vuln_context}.analysis.justification: значение не разрешено"
                )
            _string(
                analysis.get("detail"),
                f"{vuln_context}.analysis.detail",
                min_length=80,
            )
            affects = _array(vulnerability.get("affects"), f"{vuln_context}.affects")
            if len(affects) != 1:
                raise PolicyError(
                    f"{vuln_context}.affects: требуется ровно один точный package ref"
                )
            affected_ref = _exact(
                _object(affects[0], f"{vuln_context}.affects[0]").get("ref"),
                f"{vuln_context}.affects[0].ref",
            )
            component = components.get(affected_ref)
            if component is None:
                raise PolicyError(
                    f"{vuln_context}: affects ссылается на неизвестный component"
                )
            if component.get("type") != "library":
                raise PolicyError(f"{vuln_context}: package component должен быть library")
            package_key = _package_key(
                vulnerability_id, component, f"{vuln_context}.package"
            )
            if affected_ref != package_key.purl:
                raise PolicyError(
                    f"{vuln_context}: component bom-ref должен точно совпадать с purl"
                )

            vulnerability_properties = _properties(
                vulnerability.get("properties"), f"{vuln_context}.properties"
            )
            evidence = vulnerability_properties.get(
                f"{VEX_PROPERTY_PREFIX}evidence", []
            )
            if not evidence:
                raise PolicyError(f"{vuln_context}: требуется evidence URL")
            for evidence_index, evidence_url in enumerate(evidence):
                _https_url(evidence_url, f"{vuln_context}.evidence[{evidence_index}]")

            key = PolicyKey(image_digest=image_digest, package=package_key)
            if key in seen:
                raise PolicyError(f"{vuln_context}: повторное VEX-правило для exact key")
            seen.add(key)
            rules.append(
                Rule(
                    key=key,
                    mechanism="vex_not_affected",
                    rule_id=f"{serial}#{vulnerability_id}#{affected_ref}",
                )
            )
    return rules


def load_waiver_rules(
    waiver_path: Path, now: datetime
) -> tuple[list[Rule], list[Rule]]:
    context = str(waiver_path)
    document = _read_json(waiver_path, context)
    if document.get("schemaVersion") != 1:
        raise PolicyError(f"{context}: поддерживается только schemaVersion 1")

    active: list[Rule] = []
    expired: list[Rule] = []
    active_keys: set[PolicyKey] = set()
    ids: set[str] = set()
    for index, item in enumerate(_array(document.get("waivers"), f"{context}.waivers")):
        waiver_context = f"{context}.waivers[{index}]"
        waiver = _object(item, waiver_context)
        waiver_id = _exact(waiver.get("id"), f"{waiver_context}.id")
        if not WAIVER_ID.fullmatch(waiver_id):
            raise PolicyError(f"{waiver_context}.id: ожидается WAIVER-YYYY-NNN")
        if waiver_id in ids:
            raise PolicyError(f"{waiver_context}.id: идентификатор уже использован")
        ids.add(waiver_id)

        image_digest = _digest(
            waiver.get("imageDigest"), f"{waiver_context}.imageDigest"
        )
        package = _object(waiver.get("package"), f"{waiver_context}.package")
        package_key = _package_key(
            waiver.get("vulnerabilityId"), package, f"{waiver_context}.package"
        )
        _string(waiver.get("reason"), f"{waiver_context}.reason", min_length=80)
        _string(
            waiver.get("remediationPlan"),
            f"{waiver_context}.remediationPlan",
            min_length=40,
        )
        _actor(waiver.get("owner"), f"{waiver_context}.owner")
        _actor(waiver.get("approvedBy"), f"{waiver_context}.approvedBy")
        _approval_url(waiver.get("approval"), f"{waiver_context}.approval")
        evidence = _array(waiver.get("evidence"), f"{waiver_context}.evidence")
        if not evidence:
            raise PolicyError(f"{waiver_context}.evidence: нужен хотя бы один URL")
        for evidence_index, evidence_url in enumerate(evidence):
            _https_url(evidence_url, f"{waiver_context}.evidence[{evidence_index}]")

        approved_at = _timestamp(
            waiver.get("approvedAt"), f"{waiver_context}.approvedAt"
        )
        expires_at = _timestamp(
            waiver.get("expiresAt"), f"{waiver_context}.expiresAt"
        )
        if approved_at > now + FUTURE_CLOCK_SKEW:
            raise PolicyError(f"{waiver_context}: approval не может быть из будущего")
        if expires_at <= approved_at:
            raise PolicyError(f"{waiver_context}: expiresAt должен быть позже approvedAt")
        if expires_at - approved_at > MAX_WAIVER_LIFETIME:
            raise PolicyError(f"{waiver_context}: waiver не может жить дольше 30 дней")

        rule = Rule(
            key=PolicyKey(image_digest=image_digest, package=package_key),
            mechanism="temporary_waiver",
            rule_id=waiver_id,
            expires_at=expires_at,
        )
        if expires_at <= now:
            expired.append(rule)
        else:
            if rule.key in active_keys:
                raise PolicyError(
                    f"{waiver_context}: одновременно действует второй waiver для exact key"
                )
            active_keys.add(rule.key)
            active.append(rule)
    return active, expired


def evaluate(
    findings: list[Finding],
    image_digest: str,
    vex_rules: list[Rule],
    active_waivers: list[Rule],
    expired_waivers: list[Rule],
    now: datetime,
) -> dict[str, object]:
    image_digest = _digest(image_digest, "image digest")
    vex_by_key = {rule.key: rule for rule in vex_rules}
    waiver_by_key = {rule.key: rule for rule in active_waivers}
    overlap = set(vex_by_key) & set(waiver_by_key)
    if overlap:
        raise PolicyError(
            "одна exact-находка одновременно покрыта VEX и активным waiver"
        )
    expired_by_key: dict[PolicyKey, list[Rule]] = {}
    for rule in expired_waivers:
        expired_by_key.setdefault(rule.key, []).append(rule)

    raw_critical = sum(item.severity == "Critical" for item in findings)
    raw_high = sum(item.severity == "High" for item in findings)
    remaining: list[dict[str, str]] = []
    suppressed: list[dict[str, str]] = []
    expired_matches: list[dict[str, str]] = []

    for finding in findings:
        if finding.severity not in BLOCKING_SEVERITIES:
            continue
        key = PolicyKey(image_digest=image_digest, package=finding.key)
        rule = vex_by_key.get(key) or waiver_by_key.get(key)
        finding_json = {
            "vulnerabilityId": finding.key.vulnerability_id,
            "severity": finding.severity,
            "packageName": finding.key.name,
            "packageVersion": finding.key.version,
            "purl": finding.key.purl,
        }
        if rule is None:
            remaining.append(finding_json)
            for expired_rule in expired_by_key.get(key, []):
                expired_matches.append(
                    {**finding_json, "waiverId": expired_rule.rule_id}
                )
            continue
        suppressed.append(
            {
                **finding_json,
                "mechanism": rule.mechanism,
                "ruleId": rule.rule_id,
            }
        )

    result: dict[str, object] = {
        "schemaVersion": 1,
        "imageDigest": image_digest,
        "evaluatedAt": now.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "gate": {
            "threshold": "high",
            "passed": not remaining,
            "technicalErrorsSuppressible": False,
        },
        "summary": {
            "rawCritical": raw_critical,
            "rawHigh": raw_high,
            "vexSuppressed": sum(
                item["mechanism"] == "vex_not_affected" for item in suppressed
            ),
            "waiverSuppressed": sum(
                item["mechanism"] == "temporary_waiver" for item in suppressed
            ),
            "remainingCritical": sum(
                item["severity"] == "Critical" for item in remaining
            ),
            "remainingHigh": sum(item["severity"] == "High" for item in remaining),
            "expiredWaiverMatches": len(expired_matches),
        },
        "suppressed": suppressed,
        "remaining": remaining,
        "expiredWaiverMatches": expired_matches,
    }
    return result


def render_summary(result: dict[str, object]) -> str:
    summary = _object(result["summary"], "result.summary")
    gate = _object(result["gate"], "result.gate")
    status = "PASS" if gate["passed"] else "BLOCKED"
    return "\n".join(
        (
            f"### Image scan policy — `{result['imageDigest']}`",
            "",
            f"- До политики: Critical={summary['rawCritical']}, High={summary['rawHigh']}",
            f"- Подавлено: VEX={summary['vexSuppressed']}, waiver={summary['waiverSuppressed']}",
            f"- Осталось: Critical={summary['remainingCritical']}, High={summary['remainingHigh']}",
            f"- Совпало с истёкшим waiver: {summary['expiredWaiverMatches']}",
            f"- Gate: **{status}**",
            "",
        )
    )


def _write_json(path: Path, value: dict[str, object]) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--vex-dir", type=Path, required=True)
    parser.add_argument("--waivers", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    args = parser.parse_args(argv)
    now = datetime.now(UTC)

    try:
        findings = load_findings(args.report)
        vex_rules = load_vex_rules(args.vex_dir, now)
        active_waivers, expired_waivers = load_waiver_rules(args.waivers, now)
        result = evaluate(
            findings,
            args.image_digest,
            vex_rules,
            active_waivers,
            expired_waivers,
            now,
        )
    except PolicyError as exc:
        result = {
            "schemaVersion": 1,
            "imageDigest": args.image_digest,
            "evaluatedAt": now.isoformat().replace("+00:00", "Z"),
            "gate": {"threshold": "high", "passed": False},
            "policyErrors": [str(exc)],
        }
        _write_json(args.output, result)
        args.summary.write_text(
            f"### Image scan policy\n\n- Gate: **ERROR**\n- {exc}\n",
            encoding="utf-8",
        )
        print(f"policy error: {exc}", file=sys.stderr)
        return 2

    _write_json(args.output, result)
    args.summary.write_text(render_summary(result), encoding="utf-8")
    return 0 if _object(result["gate"], "result.gate")["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
