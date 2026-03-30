"""Tests for entraid_auth_001 — Weak MFA methods (SMS, voice)."""

from entralint.checks.authentication.auth_weak_mfa_methods.auth_weak_mfa_methods import (
    AuthWeakMfaMethods,
)
from entralint.core.check import Status
from entralint.core.context import TenantContext


def _ctx(**kwargs) -> TenantContext:
    return TenantContext(**kwargs)


def test_pass_sms_and_voice_disabled():
    ctx = _ctx(authentication_methods_policy={
        "authenticationMethodConfigurations": [
            {"id": "Sms", "state": "disabled"},
            {"id": "Voice", "state": "disabled"},
            {"id": "Fido2", "state": "enabled"},
        ]
    })
    findings = AuthWeakMfaMethods().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_fail_sms_enabled():
    ctx = _ctx(authentication_methods_policy={
        "authenticationMethodConfigurations": [
            {"id": "Sms", "state": "enabled"},
            {"id": "Voice", "state": "disabled"},
        ]
    })
    findings = AuthWeakMfaMethods().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL
    assert "Sms" in findings[0].title


def test_fail_both_enabled():
    ctx = _ctx(authentication_methods_policy={
        "authenticationMethodConfigurations": [
            {"id": "Sms", "state": "enabled"},
            {"id": "Voice", "state": "enabled"},
        ]
    })
    findings = AuthWeakMfaMethods().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL
    assert "Sms" in findings[0].title
    assert "Voice" in findings[0].title


def test_skip_no_policy():
    ctx = _ctx(authentication_methods_policy={})
    findings = AuthWeakMfaMethods().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.SKIPPED_PERMISSION


def test_pass_no_configs():
    ctx = _ctx(authentication_methods_policy={
        "authenticationMethodConfigurations": []
    })
    findings = AuthWeakMfaMethods().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS
