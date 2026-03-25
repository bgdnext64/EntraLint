"""Tests for JSON report formatter."""

import json

from entralint.core.check import Finding, Severity, Status
from entralint.reports.json_report import format_json


def _finding(
    check_id: str = "entraid_test_001",
    status: Status = Status.FAIL,
    severity: Severity = Severity.HIGH,
    **kwargs,
) -> Finding:
    return Finding(
        check_id=check_id,
        status=status,
        severity=severity,
        resource_type="TestResource",
        resource_id="res-1",
        title="Test finding",
        description="A test finding",
        **kwargs,
    )


def test_json_envelope_structure():
    findings = [_finding()]
    raw = format_json(findings)
    report = json.loads(raw)

    assert report["tool"] == "entralint"
    assert report["version"] == "0.1.0"
    assert "generated_at" in report
    assert "summary" in report
    assert "findings" in report


def test_json_summary_counts():
    findings = [
        _finding(status=Status.PASS),
        _finding(status=Status.FAIL),
        _finding(status=Status.FAIL),
        _finding(status=Status.SKIPPED_PERMISSION),
        _finding(status=Status.ERROR),
    ]
    report = json.loads(format_json(findings))
    summary = report["summary"]

    assert summary["total"] == 5
    assert summary["passed"] == 1
    assert summary["failed"] == 2
    assert summary["skipped"] == 1
    assert summary["errors"] == 1


def test_json_findings_serialized():
    findings = [_finding(check_id="entraid_ca_001")]
    report = json.loads(format_json(findings))

    assert len(report["findings"]) == 1
    assert report["findings"][0]["check_id"] == "entraid_ca_001"
    assert report["findings"][0]["status"] == "FAIL"
    assert report["findings"][0]["severity"] == "HIGH"


def test_json_empty_findings():
    report = json.loads(format_json([]))
    assert report["summary"]["total"] == 0
    assert report["findings"] == []


def test_json_valid_iso_timestamp():
    """generated_at should be a valid ISO 8601 UTC timestamp."""
    from datetime import datetime

    report = json.loads(format_json([]))
    ts = report["generated_at"]
    # Should parse without error
    dt = datetime.fromisoformat(ts)
    assert dt.tzinfo is not None  # must be timezone-aware
