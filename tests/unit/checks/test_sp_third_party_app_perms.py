"""Tests for entraid_sp_005 — Third-party SPs with application permissions."""

from entralint.checks.service_principals.sp_third_party_app_perms.sp_third_party_app_perms import (
    SpThirdPartyAppPerms,
)
from entralint.core.check import Status
from entralint.core.context import TenantContext
from entralint.core.models import AppRoleAssignment, ServicePrincipal


def _ctx(**kwargs) -> TenantContext:
    return TenantContext(**kwargs)


def test_pass_no_assignments():
    ctx = _ctx(app_role_assignments=[], service_principals=[])
    findings = SpThirdPartyAppPerms().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_pass_managed_identity():
    ctx = _ctx(
        service_principals=[
            ServicePrincipal(
                id="sp1", display_name="My MI",
                service_principal_type="ManagedIdentity",
                app_id="my-mi-app",
            ),
        ],
        app_role_assignments=[
            AppRoleAssignment(
                id="a1", app_role_id="some-role",
                principal_display_name="My MI", principal_id="sp1",
                resource_display_name="Microsoft Graph", resource_id="r1",
            ),
        ],
    )
    findings = SpThirdPartyAppPerms().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_pass_first_party_microsoft():
    ctx = _ctx(
        service_principals=[
            ServicePrincipal(
                id="sp1", display_name="Microsoft Graph",
                service_principal_type="Application",
                app_id="00000003-0000-0000-c000-000000000000",
            ),
        ],
        app_role_assignments=[
            AppRoleAssignment(
                id="a1", app_role_id="some-role",
                principal_display_name="Microsoft Graph", principal_id="sp1",
                resource_display_name="Microsoft Graph", resource_id="r1",
            ),
        ],
    )
    findings = SpThirdPartyAppPerms().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_fail_third_party_sp():
    ctx = _ctx(
        service_principals=[
            ServicePrincipal(
                id="sp1", display_name="Vendor App",
                service_principal_type="Application",
                app_id="deadbeef-1234-5678-abcd-000000000000",
            ),
        ],
        app_role_assignments=[
            AppRoleAssignment(
                id="a1", app_role_id="some-role",
                principal_display_name="Vendor App", principal_id="sp1",
                resource_display_name="Microsoft Graph", resource_id="r1",
            ),
        ],
    )
    findings = SpThirdPartyAppPerms().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL
    assert "Vendor App" in findings[0].title


def test_fail_multiple_assignments():
    ctx = _ctx(
        service_principals=[
            ServicePrincipal(
                id="sp1", display_name="Vendor App",
                service_principal_type="Application",
                app_id="deadbeef-1234-5678-abcd-000000000000",
            ),
        ],
        app_role_assignments=[
            AppRoleAssignment(
                id="a1", app_role_id="role1",
                principal_display_name="Vendor App", principal_id="sp1",
                resource_display_name="Microsoft Graph", resource_id="r1",
            ),
            AppRoleAssignment(
                id="a2", app_role_id="role2",
                principal_display_name="Vendor App", principal_id="sp1",
                resource_display_name="Microsoft Graph", resource_id="r1",
            ),
        ],
    )
    findings = SpThirdPartyAppPerms().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL
    assert "2 application permission(s)" in findings[0].description


def test_ignores_unknown_principal():
    """If appRoleAssignment's principalId doesn't match any SP, skip it."""
    ctx = _ctx(
        service_principals=[
            ServicePrincipal(id="sp1", display_name="Known SP"),
        ],
        app_role_assignments=[
            AppRoleAssignment(
                id="a1", app_role_id="role1",
                principal_display_name="Ghost", principal_id="sp-unknown",
                resource_display_name="Microsoft Graph", resource_id="r1",
            ),
        ],
    )
    findings = SpThirdPartyAppPerms().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS
