"""Tests for the ca_mfa_required_all_users check."""

from entralint.checks.conditional_access.ca_mfa_required_all_users.ca_mfa_required_all_users import (  # noqa: E501
    CaMfaRequiredAllUsers,
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


def _make_policy(
    *,
    state: str = "enabled",
    include_users: list[str] | None = None,
    include_apps: list[str] | None = None,
    built_in_controls: list[str] | None = None,
    auth_strength: dict[str, str] | None = None,
) -> ConditionalAccessPolicy:
    return ConditionalAccessPolicy(
        id="policy-1",
        display_name="Test Policy",
        state=state,
        conditions=ConditionalAccessConditions(
            users=ConditionalAccessConditionUsers(
                include_users=include_users or [],
            ),
            applications=ConditionalAccessConditionApps(
                include_applications=include_apps or [],
            ),
        ),
        grant_controls=ConditionalAccessGrantControls(
            built_in_controls=built_in_controls or [],
            authentication_strength=auth_strength,
        ),
    )


def test_pass_when_mfa_policy_exists() -> None:
    policy = _make_policy(
        include_users=["All"],
        include_apps=["All"],
        built_in_controls=["mfa"],
    )
    ctx = TenantContext(conditional_access_policies=[policy])
    check = CaMfaRequiredAllUsers()
    findings = check.execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_fail_when_no_policies() -> None:
    ctx = TenantContext(conditional_access_policies=[])
    check = CaMfaRequiredAllUsers()
    findings = check.execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL
    assert findings[0].severity.value == "CRITICAL"


def test_fail_when_policy_disabled() -> None:
    policy = _make_policy(
        state="disabled",
        include_users=["All"],
        include_apps=["All"],
        built_in_controls=["mfa"],
    )
    ctx = TenantContext(conditional_access_policies=[policy])
    check = CaMfaRequiredAllUsers()
    findings = check.execute(ctx)
    assert findings[0].status == Status.FAIL


def test_fail_when_not_all_users() -> None:
    policy = _make_policy(
        include_users=["group-id-123"],
        include_apps=["All"],
        built_in_controls=["mfa"],
    )
    ctx = TenantContext(conditional_access_policies=[policy])
    check = CaMfaRequiredAllUsers()
    findings = check.execute(ctx)
    assert findings[0].status == Status.FAIL


def test_fail_when_not_all_apps() -> None:
    policy = _make_policy(
        include_users=["All"],
        include_apps=["some-app-id"],
        built_in_controls=["mfa"],
    )
    ctx = TenantContext(conditional_access_policies=[policy])
    check = CaMfaRequiredAllUsers()
    findings = check.execute(ctx)
    assert findings[0].status == Status.FAIL


def test_pass_with_auth_strength() -> None:
    policy = _make_policy(
        include_users=["All"],
        include_apps=["All"],
        built_in_controls=[],
        auth_strength={"id": "phishing-resistant"},
    )
    ctx = TenantContext(conditional_access_policies=[policy])
    check = CaMfaRequiredAllUsers()
    findings = check.execute(ctx)
    assert findings[0].status == Status.PASS
