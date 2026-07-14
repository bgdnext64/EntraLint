"""Tests for entraid_user_003 - Stale user accounts."""

from datetime import UTC, datetime, timedelta

from entralint.checks.users.user_stale_accounts.user_stale_accounts import (
    UserStaleAccounts,
)
from entralint.core.check import Status
from entralint.core.context import TenantContext
from entralint.core.models import User


def _days_ago(days: int) -> str:
    """Return an ISO-8601 UTC timestamp ``days`` before now.

    Dates are computed relative to the current time so the tests do not
    silently break as real time passes the 90-day stale threshold.
    """
    dt = datetime.now(UTC) - timedelta(days=days)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# Well inside / well outside the 90-day stale threshold.
_RECENT = _days_ago(10)
_STALE = _days_ago(200)


def _ctx(**kwargs) -> TenantContext:
    return TenantContext(**kwargs)


def test_skip_no_sign_in_data():
    ctx = _ctx(users=[
        User(id="u1", display_name="Active User", account_enabled=True),
    ])
    findings = UserStaleAccounts().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.SKIPPED_LICENSE


def test_pass_recent_sign_in():
    ctx = _ctx(users=[
        User(
            id="u1", display_name="Active User",
            account_enabled=True, user_type="Member",
            sign_in_activity={
                "lastSignInDateTime": _RECENT,
            },
        ),
    ])
    findings = UserStaleAccounts().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_fail_stale_user():
    ctx = _ctx(users=[
        User(
            id="u1", display_name="Old User",
            account_enabled=True, user_type="Member",
            sign_in_activity={
                "lastSignInDateTime": _STALE,
            },
        ),
    ])
    findings = UserStaleAccounts().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL
    assert "Old User" in findings[0].title


def test_ignores_disabled_users():
    ctx = _ctx(users=[
        User(
            id="u1", display_name="Disabled User",
            account_enabled=False, user_type="Member",
            sign_in_activity={
                "lastSignInDateTime": _STALE,
            },
        ),
        User(
            id="u2", display_name="Active User",
            account_enabled=True, user_type="Member",
            sign_in_activity={
                "lastSignInDateTime": _RECENT,
            },
        ),
    ])
    findings = UserStaleAccounts().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_ignores_guest_users():
    ctx = _ctx(users=[
        User(
            id="u1", display_name="Guest",
            account_enabled=True, user_type="Guest",
            sign_in_activity={
                "lastSignInDateTime": _STALE,
            },
        ),
        User(
            id="u2", display_name="Member",
            account_enabled=True, user_type="Member",
            sign_in_activity={
                "lastSignInDateTime": _RECENT,
            },
        ),
    ])
    findings = UserStaleAccounts().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_fail_never_signed_in():
    ctx = _ctx(users=[
        User(
            id="u1", display_name="Never Signed In",
            account_enabled=True, user_type="Member",
            sign_in_activity={},
        ),
    ])
    findings = UserStaleAccounts().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL
    assert "never" in findings[0].description
