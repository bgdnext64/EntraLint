"""Tests for entraid_org_003 — Guest invitation settings."""

from entralint.checks.organization.org_guest_invite_settings.org_guest_invite_settings import (
    OrgGuestInviteSettings,
)
from entralint.core.check import Status
from entralint.core.context import TenantContext


def _ctx(**kwargs) -> TenantContext:
    return TenantContext(**kwargs)


def test_fail_everyone_can_invite():
    ctx = _ctx(authorization_policy={"allowInvitesFrom": "everyone"})
    findings = OrgGuestInviteSettings().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL


def test_fail_all_members_can_invite():
    ctx = _ctx(authorization_policy={
        "allowInvitesFrom": "adminsGuestInvitersAndAllMembers",
    })
    findings = OrgGuestInviteSettings().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL


def test_pass_admins_only():
    ctx = _ctx(authorization_policy={
        "allowInvitesFrom": "adminsAndGuestInviters",
    })
    findings = OrgGuestInviteSettings().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_pass_none():
    ctx = _ctx(authorization_policy={"allowInvitesFrom": "none"})
    findings = OrgGuestInviteSettings().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_fail_empty_policy():
    ctx = _ctx(authorization_policy={})
    findings = OrgGuestInviteSettings().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL
