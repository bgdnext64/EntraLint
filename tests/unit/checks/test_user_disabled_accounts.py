"""Tests for entraid_user_002 — Disabled user accounts."""

from entralint.checks.users.user_disabled_accounts.user_disabled_accounts import (
    UserDisabledAccounts,
)
from entralint.core.check import Status
from entralint.core.context import TenantContext
from entralint.core.models import User


def _ctx(**kwargs) -> TenantContext:
    return TenantContext(**kwargs)


def test_pass_all_enabled():
    ctx = _ctx(users=[
        User(id="u1", display_name="Alice", account_enabled=True),
        User(id="u2", display_name="Bob", account_enabled=True),
    ])
    findings = UserDisabledAccounts().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_fail_disabled_member():
    ctx = _ctx(users=[
        User(id="u1", display_name="Alice", account_enabled=False, user_type="Member"),
    ])
    findings = UserDisabledAccounts().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL
    assert "1" in findings[0].title


def test_ignores_disabled_guests():
    ctx = _ctx(users=[
        User(id="u1", display_name="Guest", account_enabled=False, user_type="Guest"),
    ])
    findings = UserDisabledAccounts().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_pass_empty():
    ctx = _ctx(users=[])
    findings = UserDisabledAccounts().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS
