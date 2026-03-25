"""Tests for core check framework types."""

from entralint.core.check import (
    BaseCheck,
    CheckMetadata,
    Finding,
    FrameworkMapping,
    Remediation,
    Severity,
    Status,
)
from entralint.core.context import TenantContext


class DummyPassCheck(BaseCheck):
    """A check that always passes — used for testing."""

    def execute(self, context: TenantContext) -> list[Finding]:
        return [
            Finding(
                check_id=self.metadata.check_id,
                status=Status.PASS,
                severity=self.metadata.severity,
                title="Dummy check passed",
            )
        ]


class DummyFailCheck(BaseCheck):
    """A check that always fails — used for testing."""

    def execute(self, context: TenantContext) -> list[Finding]:
        return [
            Finding(
                check_id=self.metadata.check_id,
                status=Status.FAIL,
                severity=self.metadata.severity,
                title="Dummy check failed",
            )
        ]


def _make_metadata(
    check_id: str = "test_001",
    severity: Severity = Severity.HIGH,
    depends_on: list[str] | None = None,
) -> CheckMetadata:
    return CheckMetadata(
        check_id=check_id,
        check_title=f"Test check {check_id}",
        service_name="TestService",
        severity=severity,
        resource_type="TestResource",
        description="A test check.",
        depends_on=depends_on or [],
    )


def test_finding_pass() -> None:
    meta = _make_metadata()
    check = DummyPassCheck(metadata=meta)
    findings = check.execute(TenantContext())
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_finding_fail() -> None:
    meta = _make_metadata()
    check = DummyFailCheck(metadata=meta)
    findings = check.execute(TenantContext())
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL


def test_check_skip() -> None:
    meta = _make_metadata()
    check = DummyPassCheck(metadata=meta)
    findings = check.skip("Missing permission X", Status.SKIPPED_PERMISSION)
    assert len(findings) == 1
    assert findings[0].status == Status.SKIPPED_PERMISSION
    assert "Missing permission X" in findings[0].description


def test_severity_ordering() -> None:
    assert Severity.CRITICAL == "CRITICAL"
    assert Severity.LOW == "LOW"


def test_framework_mapping() -> None:
    fm = FrameworkMapping(framework="CIS_M365_v5", controls=["5.2.2.2"])
    assert fm.framework == "CIS_M365_v5"
    assert "5.2.2.2" in fm.controls


def test_remediation() -> None:
    r = Remediation(
        recommendation="Fix it",
        url="https://example.com",
    )
    assert r.recommendation == "Fix it"


def test_metadata_defaults() -> None:
    meta = _make_metadata()
    assert meta.check_version == "1.0.0"
    assert meta.depends_on == []
    assert meta.required_license is None
