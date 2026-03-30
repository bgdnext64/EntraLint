"""Tests for entraid_auth_002 — Passwordless not enabled."""

from entralint.checks.authentication.auth_passwordless_not_enabled.auth_passwordless_not_enabled import (  # noqa: E501
    AuthPasswordlessNotEnabled,
)
from entralint.core.check import Status
from entralint.core.context import TenantContext


def _ctx(**kwargs) -> TenantContext:
    return TenantContext(**kwargs)


def test_pass_fido2_enabled():
    ctx = _ctx(authentication_methods_policy={
        "authenticationMethodConfigurations": [
            {"id": "Fido2", "state": "enabled"},
        ]
    })
    findings = AuthPasswordlessNotEnabled().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS
    assert "Fido2" in findings[0].title


def test_pass_authenticator_enabled():
    ctx = _ctx(authentication_methods_policy={
        "authenticationMethodConfigurations": [
            {"id": "MicrosoftAuthenticator", "state": "enabled"},
        ]
    })
    findings = AuthPasswordlessNotEnabled().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_fail_no_passwordless():
    ctx = _ctx(authentication_methods_policy={
        "authenticationMethodConfigurations": [
            {"id": "Sms", "state": "enabled"},
            {"id": "Fido2", "state": "disabled"},
        ]
    })
    findings = AuthPasswordlessNotEnabled().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL


def test_skip_no_policy():
    ctx = _ctx(authentication_methods_policy={})
    findings = AuthPasswordlessNotEnabled().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.SKIPPED_PERMISSION


def test_fail_empty_configs():
    ctx = _ctx(authentication_methods_policy={
        "authenticationMethodConfigurations": []
    })
    findings = AuthPasswordlessNotEnabled().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL
