"""Tests for ca_persistent_browser check."""

from entralint.checks.conditional_access.ca_persistent_browser.ca_persistent_browser import (
    CaPersistentBrowser,
)
from entralint.core.check import Status
from entralint.core.context import TenantContext
from entralint.core.models import (
    ConditionalAccessPolicy,
    ConditionalAccessSessionControls,
)


def _policy(
    *, persistent_browser: dict | None = None,
    sign_in_freq: dict | None = None,
    state: str = "enabled",
) -> ConditionalAccessPolicy:
    sc = None
    if persistent_browser or sign_in_freq:
        sc = ConditionalAccessSessionControls(
            persistent_browser=persistent_browser,
            sign_in_frequency=sign_in_freq,
        )
    return ConditionalAccessPolicy(
        id="p1", display_name="Session Policy", state=state,
        session_controls=sc,
    )


def test_pass_persistent_browser_never() -> None:
    p = _policy(persistent_browser={"mode": "never", "isEnabled": "true"})
    ctx = TenantContext(conditional_access_policies=[p])
    assert CaPersistentBrowser().execute(ctx)[0].status == Status.PASS


def test_pass_sign_in_frequency() -> None:
    p = _policy(sign_in_freq={"value": 1, "type": "hours", "isEnabled": "true"})
    ctx = TenantContext(conditional_access_policies=[p])
    assert CaPersistentBrowser().execute(ctx)[0].status == Status.PASS


def test_fail_no_policies() -> None:
    ctx = TenantContext(conditional_access_policies=[])
    assert CaPersistentBrowser().execute(ctx)[0].status == Status.FAIL


def test_fail_no_session_controls() -> None:
    p = _policy()
    ctx = TenantContext(conditional_access_policies=[p])
    assert CaPersistentBrowser().execute(ctx)[0].status == Status.FAIL


def test_fail_disabled() -> None:
    p = _policy(
        persistent_browser={"mode": "never"},
        state="disabled",
    )
    ctx = TenantContext(conditional_access_policies=[p])
    assert CaPersistentBrowser().execute(ctx)[0].status == Status.FAIL
