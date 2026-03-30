"""Tests for entraid_org_005 — SSPR not enabled."""

from entralint.checks.organization.org_sspr_not_enabled.org_sspr_not_enabled import (
    OrgSsprNotEnabled,
)
from entralint.core.check import Status
from entralint.core.context import TenantContext


def _ctx(**kwargs) -> TenantContext:
    return TenantContext(**kwargs)


def test_pass_methods_enabled():
    ctx = _ctx(authentication_methods_policy={
        "authenticationMethodConfigurations": [
            {"id": "MicrosoftAuthenticator", "state": "enabled"},
            {"id": "Sms", "state": "enabled"},
        ],
        "registrationEnforcement": {
            "authenticationMethodsRegistrationCampaign": {
                "state": "disabled",
            }
        },
    })
    findings = OrgSsprNotEnabled().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS
    assert "2 authentication methods" in findings[0].title


def test_pass_campaign_enabled():
    ctx = _ctx(authentication_methods_policy={
        "authenticationMethodConfigurations": [
            {"id": "MicrosoftAuthenticator", "state": "enabled"},
        ],
        "registrationEnforcement": {
            "authenticationMethodsRegistrationCampaign": {
                "state": "enabled",
            }
        },
    })
    findings = OrgSsprNotEnabled().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS
    assert "campaign" in findings[0].title.lower()


def test_fail_no_methods():
    ctx = _ctx(authentication_methods_policy={
        "authenticationMethodConfigurations": [],
    })
    findings = OrgSsprNotEnabled().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL


def test_skip_no_policy():
    ctx = _ctx(authentication_methods_policy={})
    findings = OrgSsprNotEnabled().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.SKIPPED_PERMISSION
