"""Tests for the CheckEngine — discovery, filtering, ordering, execution."""

from entralint.core.check import (
    BaseCheck,
    CheckMetadata,
    Finding,
    Severity,
    Status,
)
from entralint.core.context import TenantContext
from entralint.core.engine import CheckEngine


class AlwaysPassCheck(BaseCheck):
    def execute(self, context: TenantContext) -> list[Finding]:
        return [
            Finding(
                check_id=self.metadata.check_id,
                status=Status.PASS,
                severity=self.metadata.severity,
            )
        ]


class AlwaysFailCheck(BaseCheck):
    def execute(self, context: TenantContext) -> list[Finding]:
        return [
            Finding(
                check_id=self.metadata.check_id,
                status=Status.FAIL,
                severity=self.metadata.severity,
            )
        ]


def _meta(
    check_id: str,
    severity: Severity = Severity.HIGH,
    depends_on: list[str] | None = None,
    required_permissions: list[str] | None = None,
) -> CheckMetadata:
    return CheckMetadata(
        check_id=check_id,
        check_title=f"Check {check_id}",
        service_name="Test",
        severity=severity,
        resource_type="Test",
        description="test",
        depends_on=depends_on or [],
        required_permissions=required_permissions or [],
    )


def test_execute_pass_check() -> None:
    engine = CheckEngine(checks_dirs=[])
    engine._checks = [AlwaysPassCheck(metadata=_meta("c1"))]
    ctx = TenantContext(granted_permissions=set())
    findings = engine.execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_execute_skips_on_missing_permission() -> None:
    engine = CheckEngine(checks_dirs=[])
    engine._checks = [
        AlwaysPassCheck(
            metadata=_meta("c1", required_permissions=["Policy.Read.All"])
        )
    ]
    ctx = TenantContext(granted_permissions=set())
    findings = engine.execute(ctx)
    assert findings[0].status == Status.SKIPPED_PERMISSION


def test_execute_runs_when_permission_granted() -> None:
    engine = CheckEngine(checks_dirs=[])
    engine._checks = [
        AlwaysPassCheck(
            metadata=_meta("c1", required_permissions=["Policy.Read.All"])
        )
    ]
    ctx = TenantContext(granted_permissions={"Policy.Read.All"})
    findings = engine.execute(ctx)
    assert findings[0].status == Status.PASS


def test_dependency_skip_on_prereq_failure() -> None:
    engine = CheckEngine(checks_dirs=[])
    engine._checks = [
        AlwaysFailCheck(metadata=_meta("c1")),
        AlwaysPassCheck(metadata=_meta("c2", depends_on=["c1"])),
    ]
    ctx = TenantContext(granted_permissions=set())
    findings = engine.execute(ctx)
    assert len(findings) == 2
    assert findings[0].status == Status.FAIL
    assert findings[1].status == Status.SKIPPED_DEPENDENCY


def test_topological_sort() -> None:
    engine = CheckEngine(checks_dirs=[])
    # c2 depends on c1, but add c2 first
    engine._checks = [
        AlwaysPassCheck(metadata=_meta("c2", depends_on=["c1"])),
        AlwaysPassCheck(metadata=_meta("c1")),
    ]
    ordered = engine.build_execution_order()
    ids = [c.metadata.check_id for c in ordered]
    assert ids.index("c1") < ids.index("c2")
