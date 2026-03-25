"""Tests for ca_mfa_azure_management check."""

from entralint.checks.conditional_access.ca_mfa_azure_management.ca_mfa_azure_management import (
    AZURE_MANAGEMENT_APP_ID,
    CaMfaAzureManagement,
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


def _policy(
    *, apps: list[str], controls: list[str], state: str = "enabled",
) -> ConditionalAccessPolicy:
    return ConditionalAccessPolicy(
        id="p1", display_name="Azure MFA", state=state,
        conditions=ConditionalAccessConditions(
            users=ConditionalAccessConditionUsers(include_users=["All"]),
            applications=ConditionalAccessConditionApps(include_applications=apps),
        ),
        grant_controls=ConditionalAccessGrantControls(built_in_controls=controls),
    )


def test_pass_explicit_azure_app() -> None:
    p = _policy(apps=[AZURE_MANAGEMENT_APP_ID], controls=["mfa"])
    ctx = TenantContext(conditional_access_policies=[p])
    assert CaMfaAzureManagement().execute(ctx)[0].status == Status.PASS


def test_pass_all_apps() -> None:
    p = _policy(apps=["All"], controls=["mfa"])
    ctx = TenantContext(conditional_access_policies=[p])
    assert CaMfaAzureManagement().execute(ctx)[0].status == Status.PASS


def test_fail_no_policies() -> None:
    ctx = TenantContext(conditional_access_policies=[])
    f = CaMfaAzureManagement().execute(ctx)[0]
    assert f.status == Status.FAIL


def test_fail_wrong_app() -> None:
    p = _policy(apps=["some-other-app"], controls=["mfa"])
    ctx = TenantContext(conditional_access_policies=[p])
    assert CaMfaAzureManagement().execute(ctx)[0].status == Status.FAIL


def test_fail_disabled() -> None:
    p = _policy(apps=[AZURE_MANAGEMENT_APP_ID], controls=["mfa"], state="disabled")
    ctx = TenantContext(conditional_access_policies=[p])
    assert CaMfaAzureManagement().execute(ctx)[0].status == Status.FAIL
