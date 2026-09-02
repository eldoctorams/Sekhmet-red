from pathlib import Path

from sekhmet_red.models import Severity
from sekhmet_red.scanner import compare_reports, scan_path


FIXTURES = Path(__file__).parent / "fixtures"


def test_detects_high_confidence_attack_surface():
    report = scan_path(FIXTURES / "vulnerable")
    rule_ids = {finding.rule_id for finding in report.findings}
    assert {"SR-PI-001", "SR-PI-002", "SR-SEC-001", "SR-EXEC-001", "SR-DESER-001"} <= rule_ids
    assert report.verdict == "BLOCK"
    assert report.risk_score == 0


def test_secure_fixture_has_no_findings():
    report = scan_path(FIXTURES / "secure")
    assert report.findings == []
    assert report.verdict == "PASS"
    assert report.risk_score == 100


def test_finding_has_reproducible_evidence_fingerprint():
    first = scan_path(FIXTURES / "vulnerable")
    second = scan_path(FIXTURES / "vulnerable")
    assert [item.fingerprint for item in first.findings] == [item.fingerprint for item in second.findings]
    assert all(item.confidence >= 0.7 for item in first.findings)
    assert any(item.severity is Severity.CRITICAL for item in first.findings)


def test_baseline_comparison_detects_rug_pull():
    secure = scan_path(FIXTURES / "secure").to_dict()
    vulnerable = scan_path(FIXTURES / "vulnerable")
    comparison = compare_reports(secure, vulnerable)
    assert comparison["rug_pull_detected"] is True
    assert comparison["new"]

