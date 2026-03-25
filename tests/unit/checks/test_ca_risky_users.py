"""Tests for ca_block_risky_users check."""

from entralint.checks.conditional_access.ca_block_risky_users.ca_block_risky_users import (
    CaBlockRiskyUsers,
)
from entralint.core.check import Status
from entralint.core.context import TenantContext
from entralint.core.models import (
    ConditionalAccessConditions,
    ConditionalAccessGrantControls,
    ConditionalAccessPolicy,
)


def _policy(
    *, risk_levels: list[str], controls: list[str], state: str = "enabled",
) -> ConditionalAccessPolicy:
    return ConditionalAccessPolicy(
        id="p1", display_name="User Risk", state=state,
        conditions=ConditionalAccessConditions(user_risk_levels=risk_levels),
        grant_controls=ConditionalAccessGrantControls(built_in_controls=controls),
    )


def test_pass_high_risk_blocked() -> None:
    p = _policy(risk_levels=["high"], controls=["block"])
    ctx = TenantContext(conditional_access_policies=[p])
    assert CaBlockRiskyUsers().execute(ctx)[0].status == Status.PASS


def test_pass_mfa_required() -> None:
    p = _policy(risk_levels=["high", "medium"], controls=["mfa"])
    ctx = TenantContext(conditional_access_policies=[p])
    assert CaBlockRiskyUsers().execute(ctx)[0].status == Status.PASS


def test_fail_no_policies() -> None:
    ctx = TenantContext(conditional_access_policies=[])
    assert CaBlockRiskyUsers().execute(ctx)[0].status == Status.FAIL


def test_fail_only_medium() -> None:
    p = _policy(risk_levels=["medium"], controls=["block"])
    ctx = TenantContext(conditional_access_policies=[p])
    assert CaBlockRiskyUsers().execute(ctx)[0].status == Status.FAIL


def test_fail_disabled() -> None:
    p = _policy(risk_levels=["high"], controls=["block"], state="disabled")
    ctx = TenantContext(conditional_access_policies=[p])
    assert CaBlockRiskyUsers().execute(ctx)[0].status == Status.FAIL
