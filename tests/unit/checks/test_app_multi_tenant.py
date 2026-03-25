"""Tests for app_multi_tenant check."""

from entralint.checks.applications.app_multi_tenant.app_multi_tenant import (
    AppMultiTenant,
)
from entralint.core.check import Status
from entralint.core.context import TenantContext
from entralint.core.models import Application


def test_pass_single_tenant() -> None:
    app = Application(
        id="a1", display_name="Internal", app_id="app1",
        sign_in_audience="AzureADMyOrg",
    )
    ctx = TenantContext(applications=[app])
    assert AppMultiTenant().execute(ctx)[0].status == Status.PASS


def test_pass_no_apps() -> None:
    ctx = TenantContext(applications=[])
    assert AppMultiTenant().execute(ctx)[0].status == Status.PASS


def test_fail_multi_org() -> None:
    app = Application(
        id="a1", display_name="MultiApp", app_id="app1",
        sign_in_audience="AzureADMultipleOrgs",
    )
    ctx = TenantContext(applications=[app])
    f = AppMultiTenant().execute(ctx)[0]
    assert f.status == Status.FAIL
    assert "MultiApp" in f.title


def test_fail_personal_accounts() -> None:
    app = Application(
        id="a1", display_name="PersonalApp", app_id="app1",
        sign_in_audience="AzureADandPersonalMicrosoftAccount",
    )
    ctx = TenantContext(applications=[app])
    assert AppMultiTenant().execute(ctx)[0].status == Status.FAIL


def test_mixed_apps() -> None:
    apps = [
        Application(id="a1", display_name="OK", app_id="app1",
                     sign_in_audience="AzureADMyOrg"),
        Application(id="a2", display_name="Multi", app_id="app2",
                     sign_in_audience="AzureADMultipleOrgs"),
    ]
    ctx = TenantContext(applications=apps)
    findings = AppMultiTenant().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL
    assert "Multi" in findings[0].title
