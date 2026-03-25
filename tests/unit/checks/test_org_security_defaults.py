"""Tests for org_security_defaults check."""

from entralint.checks.organization.org_security_defaults.org_security_defaults import (
    OrgSecurityDefaults,
)
from entralint.core.check import Severity, Status
from entralint.core.context import TenantContext
from entralint.core.models import ConditionalAccessPolicy


def _ctx(
    *, sd_enabled: bool, has_ca: bool,
) -> TenantContext:
    policies = []
    if has_ca:
        policies = [
            ConditionalAccessPolicy(id="p1", display_name="CA", state="enabled")
        ]
    return TenantContext(
        conditional_access_policies=policies,
        security_defaults_policy={"isEnabled": sd_enabled},
    )


def test_pass_ca_active_sd_off() -> None:
    ctx = _ctx(sd_enabled=False, has_ca=True)
    f = OrgSecurityDefaults().execute(ctx)[0]
    assert f.status == Status.PASS


def test_pass_sd_on_no_ca() -> None:
    ctx = _ctx(sd_enabled=True, has_ca=False)
    f = OrgSecurityDefaults().execute(ctx)[0]
    assert f.status == Status.PASS


def test_fail_no_protection() -> None:
    ctx = _ctx(sd_enabled=False, has_ca=False)
    f = OrgSecurityDefaults().execute(ctx)[0]
    assert f.status == Status.FAIL
    assert f.severity == Severity.CRITICAL


def test_fail_sd_with_ca() -> None:
    ctx = _ctx(sd_enabled=True, has_ca=True)
    f = OrgSecurityDefaults().execute(ctx)[0]
    assert f.status == Status.FAIL
