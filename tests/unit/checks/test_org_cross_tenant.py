"""Tests for entraid_org_004 — Cross-tenant inbound access."""

from entralint.checks.organization.org_cross_tenant_inbound.org_cross_tenant_inbound import (
    OrgCrossTenantInbound,
)
from entralint.core.check import Status
from entralint.core.context import TenantContext


def _ctx(**kwargs) -> TenantContext:
    return TenantContext(**kwargs)


def test_fail_b2b_allows_all():
    ctx = _ctx(cross_tenant_access_policy={
        "b2bCollaborationInbound": {
            "applications": {"accessType": "allowed"},
            "usersAndGroups": {"accessType": "allowed"},
        },
        "b2bDirectConnectInbound": {
            "applications": {"accessType": "blocked"},
            "usersAndGroups": {"accessType": "blocked"},
        },
    })
    findings = OrgCrossTenantInbound().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL
    assert "B2B collaboration" in findings[0].description


def test_fail_direct_connect_allows_all():
    ctx = _ctx(cross_tenant_access_policy={
        "b2bCollaborationInbound": {
            "applications": {"accessType": "blocked"},
            "usersAndGroups": {"accessType": "blocked"},
        },
        "b2bDirectConnectInbound": {
            "applications": {"accessType": "allowed"},
            "usersAndGroups": {"accessType": "allowed"},
        },
    })
    findings = OrgCrossTenantInbound().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL
    assert "direct connect" in findings[0].description


def test_pass_both_blocked():
    ctx = _ctx(cross_tenant_access_policy={
        "b2bCollaborationInbound": {
            "applications": {"accessType": "blocked"},
            "usersAndGroups": {"accessType": "blocked"},
        },
        "b2bDirectConnectInbound": {
            "applications": {"accessType": "blocked"},
            "usersAndGroups": {"accessType": "blocked"},
        },
    })
    findings = OrgCrossTenantInbound().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_skip_no_policy():
    ctx = _ctx(cross_tenant_access_policy={})
    findings = OrgCrossTenantInbound().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.SKIPPED_PERMISSION


def test_pass_partial_block():
    """If users are blocked but apps allowed, it's not fully open."""
    ctx = _ctx(cross_tenant_access_policy={
        "b2bCollaborationInbound": {
            "applications": {"accessType": "allowed"},
            "usersAndGroups": {"accessType": "blocked"},
        },
        "b2bDirectConnectInbound": {
            "applications": {"accessType": "blocked"},
            "usersAndGroups": {"accessType": "allowed"},
        },
    })
    findings = OrgCrossTenantInbound().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS
