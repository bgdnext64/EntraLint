"""Tests for ca_block_risky_signins check."""

from entralint.checks.conditional_access.ca_block_risky_signins.ca_block_risky_signins import (
    CaBlockRiskySignins,
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
        id="p1", display_name="Risk Policy", state=state,
        conditions=ConditionalAccessConditions(sign_in_risk_levels=risk_levels),
        grant_controls=ConditionalAccessGrantControls(built_in_controls=controls),
    )


def test_pass_high_risk_blocked() -> None:
    p = _policy(risk_levels=["high", "medium"], controls=["mfa"])
    ctx = TenantContext(conditional_access_policies=[p])
    assert CaBlockRiskySignins().execute(ctx)[0].status == Status.PASS


def test_pass_block_control() -> None:
    p = _policy(risk_levels=["high"], controls=["block"])
    ctx = TenantContext(conditional_access_policies=[p])
    assert CaBlockRiskySignins().execute(ctx)[0].status == Status.PASS


def test_fail_no_policies() -> None:
    ctx = TenantContext(conditional_access_policies=[])
    assert CaBlockRiskySignins().execute(ctx)[0].status == Status.FAIL


def test_fail_only_low_risk() -> None:
    p = _policy(risk_levels=["low"], controls=["mfa"])
    ctx = TenantContext(conditional_access_policies=[p])
    assert CaBlockRiskySignins().execute(ctx)[0].status == Status.FAIL


def test_fail_disabled() -> None:
    p = _policy(risk_levels=["high"], controls=["mfa"], state="disabled")
    ctx = TenantContext(conditional_access_policies=[p])
    assert CaBlockRiskySignins().execute(ctx)[0].status == Status.FAIL
