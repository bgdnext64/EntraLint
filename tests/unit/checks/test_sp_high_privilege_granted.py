"""Tests for entraid_sp_003 — SPs with high-privilege granted app permissions."""

from entralint.checks.service_principals.sp_high_privilege_granted.sp_high_privilege_granted import (  # noqa: E501
    SpHighPrivilegeGranted,
)
from entralint.core.check import Status
from entralint.core.context import TenantContext
from entralint.core.models import AppRoleAssignment


def _ctx(**kwargs) -> TenantContext:
    return TenantContext(**kwargs)


def test_pass_no_assignments():
    ctx = _ctx(app_role_assignments=[])
    findings = SpHighPrivilegeGranted().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_pass_low_privilege_assignment():
    ctx = _ctx(app_role_assignments=[
        AppRoleAssignment(
            id="a1",
            app_role_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            principal_display_name="Safe SP",
            principal_id="sp1",
        ),
    ])
    findings = SpHighPrivilegeGranted().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_fail_directory_readwrite():
    ctx = _ctx(app_role_assignments=[
        AppRoleAssignment(
            id="a1",
            app_role_id="19dbc75e-c2e2-444c-a770-ec596d83d1bc",
            principal_display_name="Admin SP",
            principal_id="sp1",
        ),
    ])
    findings = SpHighPrivilegeGranted().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL
    assert "Admin SP" in findings[0].title
    assert "Directory.ReadWrite.All" in findings[0].description


def test_fail_multiple_perms_grouped():
    ctx = _ctx(app_role_assignments=[
        AppRoleAssignment(
            id="a1",
            app_role_id="19dbc75e-c2e2-444c-a770-ec596d83d1bc",
            principal_display_name="Multi SP",
            principal_id="sp1",
        ),
        AppRoleAssignment(
            id="a2",
            app_role_id="b633e1c5-b582-4048-a93e-9f11b44c7e96",
            principal_display_name="Multi SP",
            principal_id="sp1",
        ),
    ])
    findings = SpHighPrivilegeGranted().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL
    assert "2" in findings[0].description
