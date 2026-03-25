"""Tests for user_guest_accounts check."""

from entralint.checks.users.user_guest_accounts.user_guest_accounts import (
    UserGuestAccounts,
)
from entralint.core.check import Status
from entralint.core.context import TenantContext
from entralint.core.models import User


def test_pass_no_guests() -> None:
    users = [
        User(id="u1", display_name="Alice", user_type="Member"),
        User(id="u2", display_name="Bob", user_type="Member"),
    ]
    ctx = TenantContext(users=users)
    assert UserGuestAccounts().execute(ctx)[0].status == Status.PASS


def test_pass_no_users() -> None:
    ctx = TenantContext(users=[])
    assert UserGuestAccounts().execute(ctx)[0].status == Status.PASS


def test_fail_guest_present() -> None:
    users = [
        User(id="u1", display_name="Alice", user_type="Member"),
        User(id="u2", display_name="External", user_type="Guest"),
    ]
    ctx = TenantContext(users=users)
    f = UserGuestAccounts().execute(ctx)[0]
    assert f.status == Status.FAIL
    assert "1 guest" in f.title


def test_multiple_guests() -> None:
    users = [
        User(id=f"g{i}", display_name=f"Guest{i}", user_type="Guest")
        for i in range(5)
    ]
    ctx = TenantContext(users=users)
    f = UserGuestAccounts().execute(ctx)[0]
    assert f.status == Status.FAIL
    assert "5 guest" in f.title
