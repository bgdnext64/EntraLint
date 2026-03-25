"""Tests for entraid_app_005 — Apps requesting high-privilege Graph permissions."""

from entralint.checks.applications.app_high_privilege_permissions.app_high_privilege_permissions import (  # noqa: E501
    MS_GRAPH_APP_ID,
    AppHighPrivilegePermissions,
)
from entralint.core.check import Status
from entralint.core.context import TenantContext
from entralint.core.models import Application, RequiredResourceAccess, ResourceAccess


def _ctx(**kwargs) -> TenantContext:
    return TenantContext(**kwargs)


def test_pass_no_apps():
    ctx = _ctx(applications=[])
    findings = AppHighPrivilegePermissions().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_pass_app_with_safe_permissions():
    ctx = _ctx(applications=[
        Application(
            id="a1", display_name="Safe App", app_id="app-1",
            required_resource_access=[
                RequiredResourceAccess(
                    resource_app_id=MS_GRAPH_APP_ID,
                    resource_access=[
                        ResourceAccess(id="e1fe6dd8-ba31-4d61-89e7-88639da4683d", type="Scope"),
                    ],
                ),
            ],
        ),
    ])
    findings = AppHighPrivilegePermissions().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_fail_app_with_directory_readwrite_all():
    ctx = _ctx(applications=[
        Application(
            id="a1", display_name="Dangerous App", app_id="app-1",
            required_resource_access=[
                RequiredResourceAccess(
                    resource_app_id=MS_GRAPH_APP_ID,
                    resource_access=[
                        ResourceAccess(
                            id="19dbc75e-c2e2-444c-a770-ec596d83d1bc",
                            type="Role",
                        ),
                    ],
                ),
            ],
        ),
    ])
    findings = AppHighPrivilegePermissions().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL
    assert "Dangerous App" in findings[0].title
    assert "Directory.ReadWrite.All" in findings[0].description


def test_fail_multiple_dangerous_perms():
    ctx = _ctx(applications=[
        Application(
            id="a1", display_name="Multi-Perm App", app_id="app-1",
            required_resource_access=[
                RequiredResourceAccess(
                    resource_app_id=MS_GRAPH_APP_ID,
                    resource_access=[
                        ResourceAccess(id="19dbc75e-c2e2-444c-a770-ec596d83d1bc", type="Role"),
                        ResourceAccess(id="b633e1c5-b582-4048-a93e-9f11b44c7e96", type="Role"),
                    ],
                ),
            ],
        ),
    ])
    findings = AppHighPrivilegePermissions().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL
    assert "2" in findings[0].description


def test_ignores_non_graph_resource():
    ctx = _ctx(applications=[
        Application(
            id="a1", display_name="Other Resource", app_id="app-1",
            required_resource_access=[
                RequiredResourceAccess(
                    resource_app_id="00000002-0000-0ff1-ce00-000000000000",
                    resource_access=[
                        ResourceAccess(id="19dbc75e-c2e2-444c-a770-ec596d83d1bc", type="Role"),
                    ],
                ),
            ],
        ),
    ])
    findings = AppHighPrivilegePermissions().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS


def test_ignores_scope_type():
    """Delegated (Scope) type should not be flagged by this check."""
    ctx = _ctx(applications=[
        Application(
            id="a1", display_name="Delegated App", app_id="app-1",
            required_resource_access=[
                RequiredResourceAccess(
                    resource_app_id=MS_GRAPH_APP_ID,
                    resource_access=[
                        ResourceAccess(id="19dbc75e-c2e2-444c-a770-ec596d83d1bc", type="Scope"),
                    ],
                ),
            ],
        ),
    ])
    findings = AppHighPrivilegePermissions().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS
