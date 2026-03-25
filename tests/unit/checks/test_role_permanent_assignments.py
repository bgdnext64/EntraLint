"""Tests for entraid_role_002 — Permanent privileged role assignments."""

from entralint.checks.privileged_roles.role_permanent_assignments.role_permanent_assignments import (  # noqa: E501
    PRIVILEGED_ROLE_IDS,
    RolePermanentAssignments,
)
from entralint.core.check import Status
from entralint.core.context import TenantContext
from entralint.core.models import DirectoryRoleAssignment


def _ctx(**kwargs) -> TenantContext:
    return TenantContext(**kwargs)


GA_ROLE_ID = "62e90394-69f5-4237-9190-012177145e10"
SECURITY_ADMIN_ID = "194ae4cb-b126-40b2-bd5b-6091b380977d"


def test_fail_permanent_ga():
    ctx = _ctx(role_assignments=[
        DirectoryRoleAssignment(
            id="a1", principal_id="u1",
            role_definition_id=GA_ROLE_ID,
            principal={"displayName": "Alice"},
        ),
    ])
    findings = RolePermanentAssignments().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL
    assert "Alice" in findings[0].title
    assert "Global Administrator" in findings[0].title


def test_fail_multiple_privileged_roles():
    ctx = _ctx(role_assignments=[
        DirectoryRoleAssignment(
            id="a1", principal_id="u1",
            role_definition_id=GA_ROLE_ID,
            principal={"displayName": "Alice"},
        ),
        DirectoryRoleAssignment(
            id="a2", principal_id="u2",
            role_definition_id=SECURITY_ADMIN_ID,
            principal={"displayName": "Bob"},
        ),
    ])
    findings = RolePermanentAssignments().execute(ctx)
    assert len(findings) == 2
    assert all(f.status == Status.FAIL for f in findings)


def test_pass_no_privileged_roles():
    ctx = _ctx(role_assignments=[
        DirectoryRoleAssignment(
            id="a1", principal_id="u1",
            role_definition_id="non-privileged-role-id",
        ),
    ])
    findings = RolePermanentAssignments().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_pass_empty():
    ctx = _ctx(role_assignments=[])
    findings = RolePermanentAssignments().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_covers_all_listed_roles():
    assert GA_ROLE_ID in PRIVILEGED_ROLE_IDS
    assert SECURITY_ADMIN_ID in PRIVILEGED_ROLE_IDS
    assert len(PRIVILEGED_ROLE_IDS) == 10
