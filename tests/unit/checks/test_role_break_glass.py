"""Tests for entraid_role_003 — Break-glass accounts missing."""

from entralint.checks.privileged_roles.role_break_glass_missing.role_break_glass_missing import (
    RoleBreakGlassMissing,
)
from entralint.core.check import Status
from entralint.core.context import TenantContext
from entralint.core.models import DirectoryRoleAssignment, User

GA_ROLE_ID = "62e90394-69f5-4237-9190-012177145e10"


def _ctx(**kwargs) -> TenantContext:
    return TenantContext(**kwargs)


def test_pass_break_glass_by_name():
    ctx = _ctx(
        users=[
            User(
                id="u1", display_name="BreakGlass Admin",
                user_principal_name="breakglass@tenant.com",
            ),
            User(id="u2", display_name="Normal Admin"),
        ],
        role_assignments=[
            DirectoryRoleAssignment(id="a1", principal_id="u1", role_definition_id=GA_ROLE_ID),
            DirectoryRoleAssignment(id="a2", principal_id="u2", role_definition_id=GA_ROLE_ID),
        ],
    )
    findings = RoleBreakGlassMissing().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS
    assert "BreakGlass" in findings[0].title


def test_pass_emergency_access_name():
    ctx = _ctx(
        users=[
            User(id="u1", display_name="Emergency Access Account"),
        ],
        role_assignments=[
            DirectoryRoleAssignment(id="a1", principal_id="u1", role_definition_id=GA_ROLE_ID),
        ],
    )
    findings = RoleBreakGlassMissing().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_fail_no_break_glass():
    ctx = _ctx(
        users=[
            User(id="u1", display_name="Admin User"),
            User(id="u2", display_name="Another Admin"),
        ],
        role_assignments=[
            DirectoryRoleAssignment(id="a1", principal_id="u1", role_definition_id=GA_ROLE_ID),
            DirectoryRoleAssignment(id="a2", principal_id="u2", role_definition_id=GA_ROLE_ID),
        ],
    )
    findings = RoleBreakGlassMissing().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL
    assert "2 Global Admin" in findings[0].description


def test_skip_no_role_assignments():
    ctx = _ctx(users=[], role_assignments=[])
    findings = RoleBreakGlassMissing().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.SKIPPED_PERMISSION


def test_pass_ca_policy_exclusion():
    """Account excluded from CA policy should be detected as break-glass."""
    from entralint.core.models import (
        ConditionalAccessConditions,
        ConditionalAccessConditionUsers,
        ConditionalAccessPolicy,
    )

    ctx = _ctx(
        users=[
            User(id="u1", display_name="Regular Admin"),
        ],
        role_assignments=[
            DirectoryRoleAssignment(id="a1", principal_id="u1", role_definition_id=GA_ROLE_ID),
        ],
        conditional_access_policies=[
            ConditionalAccessPolicy(
                id="p1",
                display_name="MFA All Users",
                state="enabled",
                conditions=ConditionalAccessConditions(
                    users=ConditionalAccessConditionUsers(
                        exclude_users=["u1"],
                    ),
                ),
            ),
        ],
    )
    findings = RoleBreakGlassMissing().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS
