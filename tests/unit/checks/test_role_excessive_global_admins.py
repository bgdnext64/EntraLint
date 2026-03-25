"""Tests for entraid_role_001 — Excessive Global Administrators."""

from entralint.checks.privileged_roles.role_excessive_global_admins.role_excessive_global_admins import (  # noqa: E501
    GLOBAL_ADMIN_ROLE_TEMPLATE_ID,
    MAX_GLOBAL_ADMINS,
    RoleExcessiveGlobalAdmins,
)
from entralint.core.check import Status
from entralint.core.context import TenantContext
from entralint.core.models import DirectoryRoleAssignment


def _ctx(**kwargs) -> TenantContext:
    return TenantContext(**kwargs)


def _ga(principal_id: str, name: str = "") -> DirectoryRoleAssignment:
    return DirectoryRoleAssignment(
        id=f"assign-{principal_id}",
        principal_id=principal_id,
        role_definition_id=GLOBAL_ADMIN_ROLE_TEMPLATE_ID,
        principal={"displayName": name or principal_id},
    )


def test_pass_within_limit():
    ctx = _ctx(role_assignments=[_ga("u1"), _ga("u2")])
    findings = RoleExcessiveGlobalAdmins().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_pass_at_limit():
    ctx = _ctx(role_assignments=[
        _ga(f"u{i}") for i in range(MAX_GLOBAL_ADMINS)
    ])
    findings = RoleExcessiveGlobalAdmins().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_fail_over_limit():
    ctx = _ctx(role_assignments=[
        _ga(f"u{i}", f"Admin{i}") for i in range(MAX_GLOBAL_ADMINS + 1)
    ])
    findings = RoleExcessiveGlobalAdmins().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL
    assert str(MAX_GLOBAL_ADMINS + 1) in findings[0].title


def test_ignores_non_ga_roles():
    ctx = _ctx(role_assignments=[
        DirectoryRoleAssignment(
            id="a1", principal_id="u1",
            role_definition_id="some-other-role-id",
        ),
    ])
    findings = RoleExcessiveGlobalAdmins().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_pass_empty():
    ctx = _ctx(role_assignments=[])
    findings = RoleExcessiveGlobalAdmins().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS
