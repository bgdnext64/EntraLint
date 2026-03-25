"""Tests for entraid_sp_002 — SPs using secrets instead of certs."""

from entralint.checks.service_principals.sp_secrets_instead_of_certs.sp_secrets_instead_of_certs import (  # noqa: E501
    SpSecretsInsteadOfCerts,
)
from entralint.core.check import Status
from entralint.core.context import TenantContext
from entralint.core.models import PasswordCredential, ServicePrincipal


def _ctx(**kwargs) -> TenantContext:
    return TenantContext(**kwargs)


def test_pass_no_sps_with_secrets():
    ctx = _ctx(service_principals=[
        ServicePrincipal(id="sp1", display_name="Clean SP"),
    ])
    findings = SpSecretsInsteadOfCerts().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_fail_sp_with_secret():
    ctx = _ctx(service_principals=[
        ServicePrincipal(
            id="sp1", display_name="Secret SP",
            password_credentials=[PasswordCredential(key_id="k1")],
        ),
    ])
    findings = SpSecretsInsteadOfCerts().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL
    assert "Secret SP" in findings[0].title


def test_pass_empty():
    ctx = _ctx(service_principals=[])
    findings = SpSecretsInsteadOfCerts().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS
