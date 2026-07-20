"""Tests for SARIF 2.1.0 report formatter."""

import json

from entralint.core.check import Finding, Severity, Status
from entralint.reports.sarif_report import format_sarif


def _finding(
    check_id: str = "entraid_test_001",
    status: Status = Status.FAIL,
    severity: Severity = Severity.HIGH,
    **kwargs,
) -> Finding:
    defaults = {
        "resource_type": "ConditionalAccessPolicy",
        "resource_id": "policy-abc",
        "title": "Test finding title",
        "description": "A test finding description",
        "remediation": "Fix the thing",
    }
    defaults.update(kwargs)
    return Finding(
        check_id=check_id,
        status=status,
        severity=severity,
        **defaults,
    )


def test_sarif_schema_version():
    sarif = json.loads(format_sarif([_finding()]))
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif


def test_sarif_tool_driver():
    sarif = json.loads(format_sarif([_finding()]))
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "EntraLint"
    assert driver["version"] == "0.1.0"


def test_sarif_pass_findings_excluded():
    """PASS findings should not appear as SARIF results."""
    findings = [
        _finding(status=Status.PASS),
        _finding(check_id="entraid_ca_002", status=Status.FAIL),
    ]
    sarif = json.loads(format_sarif(findings))
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "entraid_ca_002"


def test_sarif_severity_mapping():
    critical = _finding(check_id="c1", severity=Severity.CRITICAL)
    high = _finding(check_id="c2", severity=Severity.HIGH)
    medium = _finding(check_id="c3", severity=Severity.MEDIUM)
    low = _finding(check_id="c4", severity=Severity.LOW)

    sarif = json.loads(format_sarif([critical, high, medium, low]))
    results = sarif["runs"][0]["results"]

    levels = {r["ruleId"]: r["level"] for r in results}
    assert levels["c1"] == "error"
    assert levels["c2"] == "error"
    assert levels["c3"] == "warning"
    assert levels["c4"] == "note"


def test_sarif_rules_deduplication():
    """Multiple findings from the same check should produce one rule."""
    findings = [
        _finding(check_id="entraid_app_001", resource_id="app-1"),
        _finding(check_id="entraid_app_001", resource_id="app-2"),
    ]
    sarif = json.loads(format_sarif(findings))
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert rules[0]["id"] == "entraid_app_001"


def test_sarif_logical_location():
    sarif = json.loads(format_sarif([_finding()]))
    result = sarif["runs"][0]["results"][0]
    loc = result["locations"][0]["logicalLocations"][0]
    assert loc["name"] == "policy-abc"
    assert loc["kind"] == "ConditionalAccessPolicy"


def test_sarif_physical_location_present():
    """GitHub Code Scanning requires a physicalLocation on every result."""
    sarif = json.loads(format_sarif([_finding()]))
    location = sarif["runs"][0]["results"][0]["locations"][0]
    physical = location["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == "entra/ConditionalAccessPolicy/policy-abc"
    assert physical["region"]["startLine"] == 1


def test_sarif_physical_location_uri_sanitized():
    """Resource ids with unsafe characters produce a filesystem-safe URI."""
    finding = _finding(resource_type="User", resource_id="user@contoso.com")
    sarif = json.loads(format_sarif([finding]))
    uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"]
    assert uri == "entra/User/user_contoso.com"


def test_sarif_physical_location_defaults_to_tenant():
    """Findings without resource info fall back to a tenant URI."""
    finding = _finding(resource_type="", resource_id="")
    sarif = json.loads(format_sarif([finding]))
    uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"]
    assert uri == "entra/tenant/tenant"


def test_sarif_remediation_in_message():
    sarif = json.loads(format_sarif([_finding(remediation="Apply MFA")]))
    result = sarif["runs"][0]["results"][0]
    # Remediation is appended to the message text (SARIF "fixes" requires
    # artifactChanges, which doesn't apply to config findings, so we inline
    # the recommendation into the message instead).
    assert "Apply MFA" in result["message"]["text"]
    assert "fixes" not in result


def test_sarif_skipped_level_none():
    finding = _finding(status=Status.SKIPPED_PERMISSION)
    sarif = json.loads(format_sarif([finding]))
    result = sarif["runs"][0]["results"][0]
    assert result["level"] == "none"


def test_sarif_empty_findings():
    sarif = json.loads(format_sarif([]))
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []


def test_sarif_with_check_metadata():
    """When check_metadata is provided, rules should use richer descriptions."""
    meta = {
        "entraid_test_001": {
            "description": "Full description from metadata",
            "risk": "This is risky because...",
            "remediation": {"url": "https://example.com/fix"},
        }
    }
    sarif = json.loads(format_sarif([_finding()], check_metadata=meta))
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["fullDescription"]["text"] == "Full description from metadata"
    assert rule["help"]["text"] == "This is risky because..."
    assert rule["helpUri"] == "https://example.com/fix"


def test_sarif_error_finding_level():
    finding = _finding(status=Status.ERROR)
    sarif = json.loads(format_sarif([finding]))
    result = sarif["runs"][0]["results"][0]
    assert result["level"] == "error"
