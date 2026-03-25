"""Tests for the app_credential_expiry check."""

from datetime import UTC, datetime, timedelta

from entralint.checks.applications.app_credential_expiry.app_credential_expiry import (
    AppCredentialExpiry,
)
from entralint.core.check import Severity, Status
from entralint.core.context import TenantContext
from entralint.core.models import Application, KeyCredential, PasswordCredential


def _utc_iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _make_app(
    *,
    name: str = "TestApp",
    secrets: list[PasswordCredential] | None = None,
    certs: list[KeyCredential] | None = None,
) -> Application:
    return Application(
        id="app-id-1",
        display_name=name,
        app_id="00000000-0000-0000-0000-000000000001",
        password_credentials=secrets or [],
        key_credentials=certs or [],
    )


def test_pass_when_no_apps() -> None:
    ctx = TenantContext(applications=[])
    check = AppCredentialExpiry()
    findings = check.execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_pass_when_credentials_valid() -> None:
    future = datetime.now(UTC) + timedelta(days=90)
    app = _make_app(secrets=[
        PasswordCredential(
            key_id="key1",
            display_name="my-secret",
            end_date_time=_utc_iso(future),
        ),
    ])
    ctx = TenantContext(applications=[app])
    check = AppCredentialExpiry()
    findings = check.execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_fail_when_secret_expired() -> None:
    past = datetime.now(UTC) - timedelta(days=10)
    app = _make_app(secrets=[
        PasswordCredential(
            key_id="key-expired",
            display_name="old-secret",
            end_date_time=_utc_iso(past),
        ),
    ])
    ctx = TenantContext(applications=[app])
    check = AppCredentialExpiry()
    findings = check.execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL
    assert findings[0].severity == Severity.HIGH
    assert "Expired secret" in findings[0].title


def test_fail_when_secret_expiring_soon() -> None:
    soon = datetime.now(UTC) + timedelta(days=10)
    app = _make_app(secrets=[
        PasswordCredential(
            key_id="key-soon",
            display_name="expiring-secret",
            end_date_time=_utc_iso(soon),
        ),
    ])
    ctx = TenantContext(applications=[app])
    check = AppCredentialExpiry()
    findings = check.execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL
    assert findings[0].severity == Severity.MEDIUM
    assert "Expiring secret" in findings[0].title


def test_fail_when_certificate_expired() -> None:
    past = datetime.now(UTC) - timedelta(days=5)
    app = _make_app(certs=[
        KeyCredential(
            key_id="cert-expired",
            display_name="old-cert",
            end_date_time=_utc_iso(past),
        ),
    ])
    ctx = TenantContext(applications=[app])
    check = AppCredentialExpiry()
    findings = check.execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL
    assert "Expired certificate" in findings[0].title


def test_multiple_findings_for_multiple_bad_creds() -> None:
    past = datetime.now(UTC) - timedelta(days=10)
    soon = datetime.now(UTC) + timedelta(days=5)
    app = _make_app(
        secrets=[
            PasswordCredential(
                key_id="k1", display_name="s1", end_date_time=_utc_iso(past),
            ),
        ],
        certs=[
            KeyCredential(
                key_id="k2", display_name="c1", end_date_time=_utc_iso(soon),
            ),
        ],
    )
    ctx = TenantContext(applications=[app])
    check = AppCredentialExpiry()
    findings = check.execute(ctx)
    assert len(findings) == 2
    assert all(f.status == Status.FAIL for f in findings)
