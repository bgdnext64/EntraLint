"""Tests for agent identity checks (entraid_agent_001 through entraid_agent_012)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from entralint.checks.agent_identity.agent_blocked_permission.agent_blocked_permission import (
    BLOCKED_APP_ROLE_IDS,
    AgentBlockedPermission,
)
from entralint.checks.agent_identity.agent_blueprint_all_scopes.agent_blueprint_all_scopes import (
    AgentBlueprintAllScopes,
)
from entralint.checks.agent_identity.agent_broad_permissions.agent_broad_permissions import (
    MAX_APP_ROLE_ASSIGNMENTS,
    AgentBroadPermissions,
)
from entralint.checks.agent_identity.agent_client_secrets.agent_client_secrets import (
    AgentClientSecrets,
)
from entralint.checks.agent_identity.agent_dangerous_permissions.agent_dangerous_permissions import (  # noqa: E501
    DANGEROUS_ROLE_IDS,
    AgentDangerousPermissions,
)
from entralint.checks.agent_identity.agent_disabled_by_microsoft.agent_disabled_by_microsoft import (  # noqa: E501
    AgentDisabledByMicrosoft,
)
from entralint.checks.agent_identity.agent_external_blueprint.agent_external_blueprint import (
    AgentExternalBlueprint,
)
from entralint.checks.agent_identity.agent_no_accountability.agent_no_accountability import (
    AgentNoAccountability,
)
from entralint.checks.agent_identity.agent_no_description.agent_no_description import (
    AgentNoDescription,
)
from entralint.checks.agent_identity.agent_no_inheritable_restrictions.agent_no_inheritable_restrictions import (  # noqa: E501
    AgentNoInheritableRestrictions,
)
from entralint.checks.agent_identity.agent_non_admin_creator.agent_non_admin_creator import (
    MICROSOFT_FIRST_PARTY_APPS,
    AgentNonAdminCreator,
)
from entralint.checks.agent_identity.agent_stale_credentials.agent_stale_credentials import (
    STALE_DAYS,
    AgentStaleCredentials,
)
from entralint.core.check import Severity, Status
from entralint.core.context import TenantContext
from entralint.core.models import (
    AgentIdentity,
    AgentIdentityBlueprint,
    AgentIdentityBlueprintPrincipal,
    Application,
    AppRoleAssignment,
    InheritablePermission,
    PasswordCredential,
    ServicePrincipal,
)


def _ctx(**kwargs) -> TenantContext:
    return TenantContext(**kwargs)


def _agent(
    id: str = "ag-1",
    display_name: str = "TestAgent",
    **kwargs,
) -> AgentIdentity:
    return AgentIdentity(id=id, display_name=display_name, **kwargs)


def _blueprint(
    id: str = "bp-1",
    display_name: str = "TestBlueprint",
    **kwargs,
) -> AgentIdentityBlueprint:
    return AgentIdentityBlueprint(
        id=id, display_name=display_name, **kwargs
    )


def _bpp(
    id: str = "bpp-1",
    display_name: str = "TestBPP",
    **kwargs,
) -> AgentIdentityBlueprintPrincipal:
    return AgentIdentityBlueprintPrincipal(
        id=id, display_name=display_name, **kwargs
    )


def _ara(app_role_id: str, **kwargs) -> AppRoleAssignment:
    return AppRoleAssignment(
        id=f"ara-{app_role_id[:8]}",
        app_role_id=app_role_id,
        principal_id="sp-1",
        principal_display_name="TestAgent",
        **kwargs,
    )


# ---------------------------------------------------------------
# agent_001 — Dangerous permissions
# ---------------------------------------------------------------


class TestAgentDangerousPermissions:
    def test_pass_no_agents(self):
        findings = AgentDangerousPermissions().execute(_ctx())
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    def test_pass_safe_permissions(self):
        agent = _agent(app_role_assignments=[
            _ara("00000000-0000-0000-0000-000000000001"),
        ])
        findings = AgentDangerousPermissions().execute(
            _ctx(agent_identities=[agent])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    def test_fail_files_readwrite(self):
        role_id = next(
            k for k, v in DANGEROUS_ROLE_IDS.items()
            if v == "Files.ReadWrite.All"
        )
        agent = _agent(app_role_assignments=[_ara(role_id)])
        findings = AgentDangerousPermissions().execute(
            _ctx(agent_identities=[agent])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
        assert "Files.ReadWrite.All" in findings[0].description

    def test_fail_multiple_dangerous(self):
        role_ids = list(DANGEROUS_ROLE_IDS.keys())[:3]
        agent = _agent(app_role_assignments=[
            _ara(rid) for rid in role_ids
        ])
        findings = AgentDangerousPermissions().execute(
            _ctx(agent_identities=[agent])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL

    def test_multiple_agents_mixed(self):
        safe_agent = _agent(
            id="ag-safe", display_name="Safe",
            app_role_assignments=[],
        )
        bad_role = next(iter(DANGEROUS_ROLE_IDS.keys()))
        bad_agent = _agent(
            id="ag-bad", display_name="Bad",
            app_role_assignments=[_ara(bad_role)],
        )
        findings = AgentDangerousPermissions().execute(
            _ctx(agent_identities=[safe_agent, bad_agent])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
        assert findings[0].resource_id == "ag-bad"


# ---------------------------------------------------------------
# agent_002 — Blueprint allAllowedScopes
# ---------------------------------------------------------------


class TestAgentBlueprintAllScopes:
    def test_pass_no_blueprints(self):
        findings = AgentBlueprintAllScopes().execute(_ctx())
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    def test_pass_enumerated_scopes(self):
        bp = _blueprint(inheritable_permissions=[
            InheritablePermission(
                id="ip-1", scope_collection_kind="enumeratedScopes"
            ),
        ])
        findings = AgentBlueprintAllScopes().execute(
            _ctx(agent_identity_blueprints=[bp])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    def test_fail_all_allowed(self):
        bp = _blueprint(inheritable_permissions=[
            InheritablePermission(
                id="ip-1", scope_collection_kind="allAllowedScopes"
            ),
        ])
        findings = AgentBlueprintAllScopes().execute(
            _ctx(agent_identity_blueprints=[bp])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
        assert "allAllowedScopes" in findings[0].description

    def test_pass_no_scopes(self):
        bp = _blueprint(inheritable_permissions=[
            InheritablePermission(
                id="ip-1", scope_collection_kind="noScopes"
            ),
        ])
        findings = AgentBlueprintAllScopes().execute(
            _ctx(agent_identity_blueprints=[bp])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.PASS


# ---------------------------------------------------------------
# agent_003 — Blocked permission
# ---------------------------------------------------------------


class TestAgentBlockedPermission:
    def test_pass_no_agents(self):
        findings = AgentBlockedPermission().execute(_ctx())
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    def test_fail_blocked_role(self):
        role_id = next(iter(BLOCKED_APP_ROLE_IDS.keys()))
        agent = _agent(app_role_assignments=[_ara(role_id)])
        findings = AgentBlockedPermission().execute(
            _ctx(agent_identities=[agent])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL

    def test_pass_non_blocked_role(self):
        agent = _agent(app_role_assignments=[
            _ara("00000000-0000-0000-0000-000000000099"),
        ])
        findings = AgentBlockedPermission().execute(
            _ctx(agent_identities=[agent])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.PASS


# ---------------------------------------------------------------
# agent_004 — Broad permissions
# ---------------------------------------------------------------


class TestAgentBroadPermissions:
    def test_pass_few_permissions(self):
        agent = _agent(app_role_assignments=[
            _ara(f"role-{i}") for i in range(3)
        ])
        findings = AgentBroadPermissions().execute(
            _ctx(agent_identities=[agent])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    def test_pass_at_threshold(self):
        agent = _agent(app_role_assignments=[
            _ara(f"role-{i}") for i in range(MAX_APP_ROLE_ASSIGNMENTS)
        ])
        findings = AgentBroadPermissions().execute(
            _ctx(agent_identities=[agent])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    def test_fail_over_threshold(self):
        agent = _agent(app_role_assignments=[
            _ara(f"role-{i}")
            for i in range(MAX_APP_ROLE_ASSIGNMENTS + 1)
        ])
        findings = AgentBroadPermissions().execute(
            _ctx(agent_identities=[agent])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
        assert str(MAX_APP_ROLE_ASSIGNMENTS + 1) in findings[0].title

    def test_pass_no_agents(self):
        findings = AgentBroadPermissions().execute(_ctx())
        assert len(findings) == 1
        assert findings[0].status == Status.PASS


# ---------------------------------------------------------------
# agent_005 — Non-admin creator
# ---------------------------------------------------------------


class TestAgentNonAdminCreator:
    def test_pass_known_creator(self):
        agent = _agent(created_by_app_id="app-1")
        app = Application(app_id="app-1")
        findings = AgentNonAdminCreator().execute(
            _ctx(
                agent_identities=[agent],
                applications=[app],
            )
        )
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    def test_fail_unknown_creator(self):
        agent = _agent(created_by_app_id="external-app-id")
        findings = AgentNonAdminCreator().execute(
            _ctx(agent_identities=[agent], applications=[])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
        assert "external-app-id" in findings[0].title
        # Unknown third-party creators keep the check's default HIGH severity.
        assert findings[0].severity == Severity.HIGH
        assert "third-party" in findings[0].title.lower()
        assert findings[0].raw_data["creator_is_microsoft_first_party"] is False
        assert findings[0].raw_data["creator_display_name"] == "unknown application"

    def test_fail_third_party_resolves_display_name(self):
        agent = _agent(created_by_app_id="external-app-id")
        sp = ServicePrincipal(
            app_id="external-app-id", display_name="Contoso Widgets"
        )
        findings = AgentNonAdminCreator().execute(
            _ctx(
                agent_identities=[agent],
                applications=[],
                service_principals=[sp],
            )
        )
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
        assert findings[0].severity == Severity.HIGH
        assert "Contoso Widgets" in findings[0].title
        assert findings[0].raw_data["creator_display_name"] == "Contoso Widgets"

    def test_first_party_creator_downgraded_to_low(self):
        graph_cli = next(iter(MICROSOFT_FIRST_PARTY_APPS.keys()))
        graph_cli_name = MICROSOFT_FIRST_PARTY_APPS[graph_cli]
        agent = _agent(created_by_app_id=graph_cli)
        findings = AgentNonAdminCreator().execute(
            _ctx(agent_identities=[agent], applications=[])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
        assert findings[0].severity == Severity.LOW
        assert graph_cli_name in findings[0].title
        assert "self-service" in findings[0].title.lower()
        assert findings[0].raw_data["creator_is_microsoft_first_party"] is True
        assert findings[0].raw_data["creator_display_name"] == graph_cli_name

    def test_pass_no_creator(self):
        agent = _agent(created_by_app_id=None)
        findings = AgentNonAdminCreator().execute(
            _ctx(agent_identities=[agent])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    def test_pass_no_agents(self):
        findings = AgentNonAdminCreator().execute(_ctx())
        assert len(findings) == 1
        assert findings[0].status == Status.PASS


# ---------------------------------------------------------------
# agent_006 — No accountability
# ---------------------------------------------------------------


class TestAgentNoAccountability:
    def test_pass_agent_with_owner(self):
        agent = _agent(owners=[{"id": "u1", "displayName": "User1"}])
        findings = AgentNoAccountability().execute(
            _ctx(agent_identities=[agent])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    def test_pass_agent_with_sponsor(self):
        agent = _agent(sponsors=[{"id": "u2", "displayName": "User2"}])
        findings = AgentNoAccountability().execute(
            _ctx(agent_identities=[agent])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    def test_fail_agent_no_owner_no_sponsor(self):
        agent = _agent(owners=[], sponsors=[])
        findings = AgentNoAccountability().execute(
            _ctx(agent_identities=[agent])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
        assert "no owner or sponsor" in findings[0].title.lower()

    def test_fail_blueprint_no_owner_no_sponsor(self):
        bp = _blueprint(owners=[], sponsors=[])
        findings = AgentNoAccountability().execute(
            _ctx(agent_identity_blueprints=[bp])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
        assert "Blueprint" in findings[0].title

    def test_pass_both_have_owners(self):
        agent = _agent(owners=[{"id": "u1"}])
        bp = _blueprint(sponsors=[{"id": "u2"}])
        findings = AgentNoAccountability().execute(
            _ctx(
                agent_identities=[agent],
                agent_identity_blueprints=[bp],
            )
        )
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    def test_pass_empty(self):
        findings = AgentNoAccountability().execute(_ctx())
        assert len(findings) == 1
        assert findings[0].status == Status.PASS


# ---------------------------------------------------------------
# agent_007 — External blueprint principal
# ---------------------------------------------------------------


class TestAgentExternalBlueprint:
    def test_pass_same_tenant(self):
        bpp = _bpp(app_owner_organization_id="tenant-1")
        findings = AgentExternalBlueprint().execute(
            _ctx(
                tenant_id="tenant-1",
                agent_identity_blueprint_principals=[bpp],
            )
        )
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    def test_fail_external(self):
        bpp = _bpp(app_owner_organization_id="other-tenant")
        findings = AgentExternalBlueprint().execute(
            _ctx(
                tenant_id="my-tenant",
                agent_identity_blueprint_principals=[bpp],
            )
        )
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
        assert "External" in findings[0].title

    def test_pass_no_principals(self):
        findings = AgentExternalBlueprint().execute(
            _ctx(tenant_id="my-tenant")
        )
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    def test_pass_no_owner_org(self):
        bpp = _bpp(app_owner_organization_id=None)
        findings = AgentExternalBlueprint().execute(
            _ctx(
                tenant_id="my-tenant",
                agent_identity_blueprint_principals=[bpp],
            )
        )
        assert len(findings) == 1
        assert findings[0].status == Status.PASS


# ---------------------------------------------------------------
# agent_008 — Client secrets
# ---------------------------------------------------------------


class TestAgentClientSecrets:
    def test_pass_no_blueprints(self):
        findings = AgentClientSecrets().execute(_ctx())
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    def test_pass_federated_only(self):
        bp = _blueprint(
            federated_identity_credentials=[{"id": "fic-1"}],
            password_credentials=[],
        )
        findings = AgentClientSecrets().execute(
            _ctx(agent_identity_blueprints=[bp])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    def test_fail_secrets_no_federated(self):
        bp = _blueprint(
            password_credentials=[
                PasswordCredential(key_id="k1"),
            ],
            federated_identity_credentials=[],
        )
        findings = AgentClientSecrets().execute(
            _ctx(agent_identity_blueprints=[bp])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
        assert "client secrets" in findings[0].title.lower()

    def test_pass_both_secrets_and_federated(self):
        bp = _blueprint(
            password_credentials=[
                PasswordCredential(key_id="k1"),
            ],
            federated_identity_credentials=[{"id": "fic-1"}],
        )
        findings = AgentClientSecrets().execute(
            _ctx(agent_identity_blueprints=[bp])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    def test_pass_no_credentials(self):
        bp = _blueprint()
        findings = AgentClientSecrets().execute(
            _ctx(agent_identity_blueprints=[bp])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.PASS


# ---------------------------------------------------------------
# agent_009 — Stale credentials
# ---------------------------------------------------------------


class TestAgentStaleCredentials:
    def test_pass_recent_agent(self):
        recent = (
            datetime.now(tz=UTC) - timedelta(days=10)
        ).isoformat()
        agent = _agent(created_date_time=recent)
        findings = AgentStaleCredentials().execute(
            _ctx(agent_identities=[agent])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    def test_fail_old_agent(self):
        old = (
            datetime.now(tz=UTC) - timedelta(days=STALE_DAYS + 1)
        ).isoformat()
        agent = _agent(created_date_time=old)
        findings = AgentStaleCredentials().execute(
            _ctx(agent_identities=[agent])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
        assert "days old" in findings[0].title

    def test_pass_disabled_old_agent(self):
        old = (
            datetime.now(tz=UTC) - timedelta(days=STALE_DAYS + 1)
        ).isoformat()
        agent = _agent(
            created_date_time=old, account_enabled=False
        )
        findings = AgentStaleCredentials().execute(
            _ctx(agent_identities=[agent])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    def test_pass_no_agents(self):
        findings = AgentStaleCredentials().execute(_ctx())
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    def test_pass_no_created_date(self):
        agent = _agent(created_date_time=None)
        findings = AgentStaleCredentials().execute(
            _ctx(agent_identities=[agent])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.PASS


# ---------------------------------------------------------------
# agent_010 — No inheritable restrictions
# ---------------------------------------------------------------


class TestAgentNoInheritableRestrictions:
    def test_pass_has_restrictions(self):
        bp = _blueprint(inheritable_permissions=[
            InheritablePermission(
                id="ip-1", scope_collection_kind="enumeratedScopes"
            ),
        ])
        findings = AgentNoInheritableRestrictions().execute(
            _ctx(agent_identity_blueprints=[bp])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    def test_fail_empty_restrictions(self):
        bp = _blueprint(inheritable_permissions=[])
        findings = AgentNoInheritableRestrictions().execute(
            _ctx(agent_identity_blueprints=[bp])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL

    def test_pass_no_blueprints(self):
        findings = AgentNoInheritableRestrictions().execute(_ctx())
        assert len(findings) == 1
        assert findings[0].status == Status.PASS


# ---------------------------------------------------------------
# agent_011 — Disabled by Microsoft
# ---------------------------------------------------------------


class TestAgentDisabledByMicrosoft:
    def test_pass_not_disabled(self):
        agent = _agent(disabled_by_microsoft_status="NotDisabled")
        findings = AgentDisabledByMicrosoft().execute(
            _ctx(agent_identities=[agent])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    def test_pass_null_status(self):
        agent = _agent(disabled_by_microsoft_status=None)
        findings = AgentDisabledByMicrosoft().execute(
            _ctx(agent_identities=[agent])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    def test_fail_disabled(self):
        agent = _agent(
            disabled_by_microsoft_status=(
                "DisabledDueToViolationOfServicesAgreement"
            )
        )
        findings = AgentDisabledByMicrosoft().execute(
            _ctx(agent_identities=[agent])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
        assert "disabled by microsoft" in findings[0].title.lower()

    def test_pass_no_agents(self):
        findings = AgentDisabledByMicrosoft().execute(_ctx())
        assert len(findings) == 1
        assert findings[0].status == Status.PASS


# ---------------------------------------------------------------
# agent_012 — No description
# ---------------------------------------------------------------


class TestAgentNoDescription:
    def test_pass_has_description(self):
        bp = _blueprint(description="My agent blueprint")
        findings = AgentNoDescription().execute(
            _ctx(agent_identity_blueprints=[bp])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    def test_pass_has_info(self):
        bp = _blueprint(
            description=None,
            info={"termsOfServiceUrl": "https://example.com"},
        )
        findings = AgentNoDescription().execute(
            _ctx(agent_identity_blueprints=[bp])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    def test_fail_no_description_no_info(self):
        bp = _blueprint(description=None, info=None)
        findings = AgentNoDescription().execute(
            _ctx(agent_identity_blueprints=[bp])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL

    def test_fail_info_all_null_values(self):
        """Graph API returns info dict with all-null URLs — treat as empty."""
        bp = _blueprint(
            description=None,
            info={
                "logoUrl": None,
                "marketingUrl": None,
                "privacyStatementUrl": None,
                "supportUrl": None,
                "termsOfServiceUrl": None,
            },
        )
        findings = AgentNoDescription().execute(
            _ctx(agent_identity_blueprints=[bp])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL

    def test_fail_agent_no_display_name(self):
        agent = _agent(
            id="some-guid", display_name="some-guid"
        )
        findings = AgentNoDescription().execute(
            _ctx(agent_identities=[agent])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL

    def test_pass_agent_has_name(self):
        agent = _agent(display_name="My Cool Agent")
        findings = AgentNoDescription().execute(
            _ctx(agent_identities=[agent])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    def test_pass_empty(self):
        findings = AgentNoDescription().execute(_ctx())
        assert len(findings) == 1
        assert findings[0].status == Status.PASS
