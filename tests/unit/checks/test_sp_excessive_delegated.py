"""Tests for entraid_sp_004 — Excessive admin-consented delegated permissions."""

from entralint.checks.service_principals.sp_excessive_delegated.sp_excessive_delegated import (
    SpExcessiveDelegated,
)
from entralint.core.check import Status
from entralint.core.context import TenantContext
from entralint.core.models import ServicePrincipal


def _ctx(**kwargs) -> TenantContext:
    return TenantContext(**kwargs)


def test_pass_no_grants():
    ctx = _ctx(oauth2_permission_grants=[])
    findings = SpExcessiveDelegated().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_pass_user_consent_only():
    ctx = _ctx(oauth2_permission_grants=[
        {
            "clientId": "sp1",
            "consentType": "Principal",
            "scope": "Mail.ReadWrite User.Read",
        },
    ])
    findings = SpExcessiveDelegated().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_pass_admin_consent_safe_scopes():
    ctx = _ctx(oauth2_permission_grants=[
        {
            "clientId": "sp1",
            "consentType": "AllPrincipals",
            "scope": "User.Read openid profile",
        },
    ])
    findings = SpExcessiveDelegated().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_fail_admin_consent_mail_readwrite():
    ctx = _ctx(
        service_principals=[
            ServicePrincipal(id="sp1", display_name="Risky App"),
        ],
        oauth2_permission_grants=[
            {
                "clientId": "sp1",
                "consentType": "AllPrincipals",
                "scope": "User.Read Mail.ReadWrite",
            },
        ],
    )
    findings = SpExcessiveDelegated().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL
    assert "Risky App" in findings[0].title
    assert "mail.readwrite" in findings[0].description


def test_fail_multiple_dangerous_scopes():
    ctx = _ctx(
        service_principals=[
            ServicePrincipal(id="sp1", display_name="Mega App"),
        ],
        oauth2_permission_grants=[
            {
                "clientId": "sp1",
                "consentType": "AllPrincipals",
                "scope": "Mail.ReadWrite Files.ReadWrite.All Directory.ReadWrite.All",
            },
        ],
    )
    findings = SpExcessiveDelegated().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL
    # Should list all 3 dangerous scopes
    assert "directory.readwrite.all" in findings[0].description
    assert "files.readwrite.all" in findings[0].description
    assert "mail.readwrite" in findings[0].description


def test_resolves_sp_name():
    ctx = _ctx(
        service_principals=[
            ServicePrincipal(id="sp-abc", display_name="Named App"),
        ],
        oauth2_permission_grants=[
            {
                "clientId": "sp-abc",
                "consentType": "AllPrincipals",
                "scope": "Mail.Send",
            },
        ],
    )
    findings = SpExcessiveDelegated().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL
    assert "Named App" in findings[0].title


def test_falls_back_to_client_id():
    ctx = _ctx(
        service_principals=[],
        oauth2_permission_grants=[
            {
                "clientId": "unknown-sp",
                "consentType": "AllPrincipals",
                "scope": "Mail.ReadWrite",
            },
        ],
    )
    findings = SpExcessiveDelegated().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL
    assert "unknown-sp" in findings[0].title
