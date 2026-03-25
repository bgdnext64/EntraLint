"""Tests for app_secrets_instead_of_certs check."""

from entralint.checks.applications.app_secrets_instead_of_certs.app_secrets_instead_of_certs import (  # noqa: E501
    AppSecretsInsteadOfCerts,
)
from entralint.core.check import Status
from entralint.core.context import TenantContext
from entralint.core.models import Application, KeyCredential, PasswordCredential


def test_pass_no_apps() -> None:
    ctx = TenantContext(applications=[])
    assert AppSecretsInsteadOfCerts().execute(ctx)[0].status == Status.PASS


def test_pass_app_with_cert_only() -> None:
    app = Application(
        id="a1", display_name="CertApp", app_id="app1",
        key_credentials=[KeyCredential(key_id="k1")],
    )
    ctx = TenantContext(applications=[app])
    assert AppSecretsInsteadOfCerts().execute(ctx)[0].status == Status.PASS


def test_fail_app_with_secret() -> None:
    app = Application(
        id="a1", display_name="SecretApp", app_id="app1",
        password_credentials=[PasswordCredential(key_id="s1")],
    )
    ctx = TenantContext(applications=[app])
    f = AppSecretsInsteadOfCerts().execute(ctx)[0]
    assert f.status == Status.FAIL
    assert "SecretApp" in f.title


def test_multiple_apps_with_secrets() -> None:
    apps = [
        Application(
            id=f"a{i}", display_name=f"App{i}", app_id=f"app{i}",
            password_credentials=[PasswordCredential(key_id=f"s{i}")],
        )
        for i in range(3)
    ]
    ctx = TenantContext(applications=apps)
    findings = AppSecretsInsteadOfCerts().execute(ctx)
    assert len(findings) == 3
    assert all(f.status == Status.FAIL for f in findings)
