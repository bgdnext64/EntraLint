"""Tests for the ca_mfa_required_admins check."""

from entralint.checks.conditional_access.ca_mfa_required_admins.ca_mfa_required_admins import (
    CaMfaRequiredAdmins,
)
from entralint.core.check import Status
from entralint.core.context import TenantContext
from entralint.core.models import (
    ConditionalAccessConditionApps,
    ConditionalAccessConditions,
    ConditionalAccessConditionUsers,
    ConditionalAccessGrantControls,
    ConditionalAccessPolicy,
)

GLOBAL_ADMIN_ROLE_ID = "62e90394-69f5-4237-9190-012177145e10"


def _make_policy(
    *,
    state: str = "enabled",
    include_roles: list[str] | None = None,
    include_users: list[str] | None = None,
    built_in_controls: list[str] | None = None,
    auth_strength: dict[str, str] | None = None,
) -> ConditionalAccessPolicy:
    return ConditionalAccessPolicy(
        id="policy-admin",
        display_name="Admin MFA Policy",
        state=state,
        conditions=ConditionalAccessConditions(
            users=ConditionalAccessConditionUsers(
                include_users=include_users or [],
                include_roles=include_roles or [],
            ),
            applications=ConditionalAccessConditionApps(
                include_applications=["All"],
            ),
        ),
        grant_controls=ConditionalAccessGrantControls(
            built_in_controls=built_in_controls or [],
            authentication_strength=auth_strength,
        ),
    )


def test_pass_when_admin_mfa_policy_exists() -> None:
    policy = _make_policy(
        include_roles=[GLOBAL_ADMIN_ROLE_ID],
        built_in_controls=["mfa"],
    )
    ctx = TenantContext(conditional_access_policies=[policy])
    check = CaMfaRequiredAdmins()
    findings = check.execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_fail_when_no_policies() -> None:
    ctx = TenantContext(conditional_access_policies=[])
    check = CaMfaRequiredAdmins()
    findings = check.execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL
    assert findings[0].severity.value == "CRITICAL"


def test_fail_when_policy_disabled() -> None:
    policy = _make_policy(
        state="disabled",
        include_roles=[GLOBAL_ADMIN_ROLE_ID],
        built_in_controls=["mfa"],
    )
    ctx = TenantContext(conditional_access_policies=[policy])
    check = CaMfaRequiredAdmins()
    findings = check.execute(ctx)
    assert findings[0].status == Status.FAIL


def test_fail_when_no_roles_targeted() -> None:
    policy = _make_policy(
        include_users=["All"],
        built_in_controls=["mfa"],
    )
    ctx = TenantContext(conditional_access_policies=[policy])
    check = CaMfaRequiredAdmins()
    findings = check.execute(ctx)
    assert findings[0].status == Status.FAIL


def test_pass_with_auth_strength() -> None:
    policy = _make_policy(
        include_roles=[GLOBAL_ADMIN_ROLE_ID],
        auth_strength={"id": "phishing-resistant"},
    )
    ctx = TenantContext(conditional_access_policies=[policy])
    check = CaMfaRequiredAdmins()
    findings = check.execute(ctx)
    assert findings[0].status == Status.PASS
