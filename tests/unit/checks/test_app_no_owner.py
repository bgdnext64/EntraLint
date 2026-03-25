"""Tests for entraid_app_004 — App registrations with no owner."""

from entralint.checks.applications.app_no_owner.app_no_owner import AppNoOwner
from entralint.core.check import Status
from entralint.core.context import TenantContext
from entralint.core.models import Application


def _ctx(**kwargs) -> TenantContext:
    return TenantContext(**kwargs)


def test_pass_all_apps_have_owners():
    ctx = _ctx(applications=[
        Application(app_id="a1", display_name="App1", owners=[{"id": "owner1"}]),
        Application(app_id="a2", display_name="App2", owners=[{"id": "owner2"}]),
    ])
    findings = AppNoOwner().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_fail_app_without_owner():
    ctx = _ctx(applications=[
        Application(app_id="a1", display_name="Orphaned", owners=[]),
        Application(app_id="a2", display_name="Owned", owners=[{"id": "o1"}]),
    ])
    findings = AppNoOwner().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL
    assert "Orphaned" in findings[0].title


def test_fail_multiple_ownerless_apps():
    ctx = _ctx(applications=[
        Application(app_id="a1", display_name="Orphaned1", owners=[]),
        Application(app_id="a2", display_name="Orphaned2", owners=[]),
    ])
    findings = AppNoOwner().execute(ctx)
    assert len(findings) == 2
    assert all(f.status == Status.FAIL for f in findings)


def test_pass_no_apps():
    ctx = _ctx(applications=[])
    findings = AppNoOwner().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS
