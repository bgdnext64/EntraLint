"""Tests for entraid_org_002 — User consent to applications."""

from entralint.checks.organization.org_user_consent.org_user_consent import (
    OrgUserConsent,
)
from entralint.core.check import Status
from entralint.core.context import TenantContext


def _ctx(**kwargs) -> TenantContext:
    return TenantContext(**kwargs)


def test_fail_permissive_consent():
    ctx = _ctx(authorization_policy={
        "defaultUserRolePermissions": {
            "permissionGrantPoliciesAssigned": [
                "managePermissionGrantsForSelf.microsoft-user-default-legacy"
            ],
        },
    })
    findings = OrgUserConsent().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL


def test_pass_restricted_consent():
    ctx = _ctx(authorization_policy={
        "defaultUserRolePermissions": {
            "permissionGrantPoliciesAssigned": [
                "managePermissionGrantsForSelf.microsoft-user-default-recommended"
            ],
        },
    })
    findings = OrgUserConsent().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_pass_no_consent_policies_in_default_role():
    """When defaultUserRolePermissions exists but has empty consent list."""
    ctx = _ctx(authorization_policy={
        "defaultUserRolePermissions": {
            "permissionGrantPoliciesAssigned": [],
        },
    })
    findings = OrgUserConsent().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_fail_empty_authorization_policy():
    """When authorization policy is empty (not fetched), check reports FAIL."""
    ctx = _ctx(authorization_policy={})
    findings = OrgUserConsent().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL
