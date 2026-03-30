"""Tests for HTML report formatter."""

from entralint.core.check import Finding, FrameworkMapping, Severity, Status
from entralint.reports.html_report import format_html


def _find(
    *,
    check_id: str = "entraid_ca_001",
    status: Status = Status.FAIL,
    severity: Severity = Severity.CRITICAL,
    title: str = "No MFA policy",
    description: str = "MFA is not required.",
    remediation: str = "Enable MFA.",
    resource_id: str = "",
    frameworks: list[FrameworkMapping] | None = None,
) -> Finding:
    return Finding(
        check_id=check_id,
        status=status,
        severity=severity,
        title=title,
        description=description,
        remediation=remediation,
        resource_id=resource_id,
        frameworks=frameworks or [],
    )


def test_html_contains_doctype():
    html = format_html([_find()])
    assert html.startswith("<!DOCTYPE html>")


def test_html_contains_scan_data():
    html = format_html([_find()])
    assert "const SCAN_DATA =" in html


def test_html_summary_counts():
    findings = [
        _find(status=Status.FAIL),
        _find(status=Status.PASS, check_id="entraid_ca_002", title="Pass"),
        _find(
            status=Status.SKIPPED_PERMISSION,
            check_id="entraid_ca_003",
            title="Skip",
        ),
    ]
    html = format_html(findings)
    # Total should be 3 (in the card values)
    assert '"total": 3' in html
    assert '"failed": 1' in html
    assert '"passed": 1' in html
    assert '"skipped": 1' in html


def test_html_severity_counts():
    findings = [
        _find(severity=Severity.CRITICAL),
        _find(severity=Severity.HIGH, check_id="entraid_ca_002", title="H"),
        _find(severity=Severity.HIGH, check_id="entraid_ca_003", title="H2"),
    ]
    html = format_html(findings)
    # SCAN_DATA JSON includes severity_counts
    assert '"CRITICAL": 1' in html
    assert '"HIGH": 2' in html


def test_html_tenant_id():
    html = format_html([_find()], tenant_id="abc-123")
    assert "abc-123" in html


def test_html_framework_mappings():
    fw = FrameworkMapping(framework="CIS", controls=["5.2.2.2"])
    html = format_html([_find(frameworks=[fw])])
    assert "CIS" in html
    assert "5.2.2.2" in html


def test_html_check_metadata_enrichment():
    meta = {
        "entraid_ca_001": {
            "risk": "Accounts can be compromised without MFA.",
            "remediation": {"url": "https://example.com/fix"},
        }
    }
    html = format_html([_find()], check_metadata=meta)
    assert "Accounts can be compromised" in html
    assert "https://example.com/fix" in html


def test_html_empty_findings():
    html = format_html([])
    assert "<!DOCTYPE html>" in html
    assert '"total": 0' in html
    assert "No failures" in html  # donut chart shows "No failures"


def test_html_escapes_special_characters():
    f = _find(title='<script>alert("xss")</script>')
    html = format_html([f])
    # The title should be in the JSON data, escaped by json.dumps
    assert '<script>alert("xss")</script>' not in html
    assert "alert" in html  # Still present but escaped


def test_html_category_breakdown():
    findings = [
        _find(check_id="entraid_ca_001"),
        _find(check_id="entraid_ca_002", title="Another CA"),
        _find(check_id="entraid_app_001", title="App check"),
    ]
    html = format_html(findings)
    assert '"ca": 2' in html
    assert '"app": 1' in html


def test_html_errors_card_hidden_when_zero():
    html = format_html([_find()])
    # Errors card display should be "none" when 0 errors
    assert 'display:none' in html


def test_html_errors_card_shown_when_nonzero():
    html = format_html([_find(status=Status.ERROR)])
    assert 'display:block' in html
