"""Tests for display_scan_summary output."""

from io import StringIO

from rich.console import Console

from entralint.core.check import Finding, Severity, Status


def _finding(
    check_id: str = "test_001",
    status: Status = Status.FAIL,
    severity: Severity = Severity.MEDIUM,
) -> Finding:
    return Finding(
        check_id=check_id,
        status=status,
        severity=severity,
        title="test",
    )


def _capture_summary(findings: list[Finding]) -> str:
    """Call display_scan_summary and capture the text output."""
    import entralint.cli.output as mod

    buf = StringIO()
    original = mod.console
    mod.console = Console(file=buf, width=120, no_color=True)
    try:
        mod.display_scan_summary(findings)
    finally:
        mod.console = original
    return buf.getvalue()


def test_summary_shows_check_count_vs_finding_count():
    """Checks shows unique check IDs, not total findings."""
    findings = [
        _finding(check_id="app_001"),
        _finding(check_id="app_001"),
        _finding(check_id="app_001"),
        _finding(check_id="ca_001"),
        _finding(check_id="ca_002", status=Status.PASS),
    ]
    text = _capture_summary(findings)
    assert "Checks: 3" in text
    assert "Findings: 5" in text


def test_summary_counts_passed():
    findings = [
        _finding(status=Status.PASS),
        _finding(status=Status.PASS, check_id="test_002"),
        _finding(status=Status.FAIL, check_id="test_003"),
    ]
    text = _capture_summary(findings)
    assert "Passed: 2" in text
    assert "Failed: 1" in text


def test_summary_counts_skipped():
    findings = [
        _finding(status=Status.SKIPPED_PERMISSION, check_id="a"),
        _finding(status=Status.SKIPPED_LICENSE, check_id="b"),
        _finding(status=Status.SKIPPED_DEPENDENCY, check_id="c"),
    ]
    text = _capture_summary(findings)
    assert "Skipped: 3" in text


def test_summary_counts_errors():
    findings = [_finding(status=Status.ERROR)]
    text = _capture_summary(findings)
    assert "Errors: 1" in text


def test_summary_empty_findings():
    text = _capture_summary([])
    assert "Checks: 0" in text
    assert "Findings: 0" in text
