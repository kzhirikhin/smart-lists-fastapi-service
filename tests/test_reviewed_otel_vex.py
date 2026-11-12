"""Фактический VEX/record разрешают только одну exact FIPS-находку."""
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from scripts import promote_reviewed_otel as promotion
from scripts.evaluate_image_scan import Finding, PackageKey, evaluate, load_vex_rules


def reviewed_record():
    import json
    record = json.loads(promotion.RECORD.read_text())
    # Исторический record должен оставаться валидным артефактом после expiry;
    # реальное текущее время проверяет сам promotion перед mutation.
    reviewed = datetime.fromisoformat(record["reviewedAt"].replace("Z", "+00:00"))
    return promotion.load_record(promotion.RECORD, reviewed + timedelta(seconds=1)), reviewed


def test_committed_review_record_matches_exact_vex():
    record, reviewed = reviewed_record()
    promotion.validate_review_binding(record, promotion.ROOT / 'security/vex')
    with pytest.raises(ValueError):
        promotion.load_record(promotion.RECORD, datetime.fromisoformat(record["expiresAt"].replace("Z", "+00:00")))


def test_real_policy_does_not_hide_any_other_high():
    record, reviewed = reviewed_record()
    rules = load_vex_rules(promotion.ROOT / 'security/vex', reviewed + timedelta(seconds=1))
    expected = PackageKey('CVE-2026-119170', 'python', '3.14.10', 'pkg:generic/python@3.14.10')
    findings = [Finding(expected, 'High', 'fixed', ('3.14.11',)), Finding(PackageKey('CVE-2026-999999', 'python', '3.14.10', 'pkg:generic/python@3.14.10'), 'High', 'fixed', ('3.14.11',))]
    result = evaluate(findings, record['imageDigest'], rules, [], [], reviewed)
    assert result['summary']['vexSuppressed'] == 1
    assert result['summary']['remainingHigh'] == 1
    assert result['gate']['passed'] is False
    other = evaluate(findings[:1], record['parentDigest'], rules, [], [], reviewed)
    assert other['summary']['vexSuppressed'] == 0
    assert other['summary']['remainingHigh'] == 1
