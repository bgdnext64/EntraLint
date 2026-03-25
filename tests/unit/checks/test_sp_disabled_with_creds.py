"""Tests for entraid_sp_001 — Disabled SPs with active credentials."""

from entralint.checks.service_principals.sp_disabled_with_creds.sp_disabled_with_creds import (
    SpDisabledWithCreds,
)
from entralint.core.check import Status
from entralint.core.context import TenantContext
from entralint.core.models import PasswordCredential, ServicePrincipal


def _ctx(**kwargs) -> TenantContext:
    return TenantContext(**kwargs)


def test_pass_no_disabled_sps_with_creds():
    ctx = _ctx(service_principals=[
        ServicePrincipal(
            id="sp1", display_name="Active SP",
            account_enabled=True,
            password_credentials=[PasswordCredential(key_id="k1")],
        ),
        ServicePrincipal(
            id="sp2", display_name="Disabled Clean",
            account_enabled=False,
            password_credentials=[],
        ),
    ])
    findings = SpDisabledWithCreds().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_fail_disabled_sp_with_secret():
    ctx = _ctx(service_principals=[
        ServicePrincipal(
            id="sp1", display_name="Bad SP",
            account_enabled=False,
            password_credentials=[PasswordCredential(key_id="k1")],
        ),
    ])
    findings = SpDisabledWithCreds().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL
    assert "Bad SP" in findings[0].title


def test_pass_empty():
    ctx = _ctx(service_principals=[])
    findings = SpDisabledWithCreds().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS
