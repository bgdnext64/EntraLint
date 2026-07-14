"""Tests for extended agent identity checks (entraid_agent_013-018).

Covers the delegated-permission, multi-tenant blueprint, federated-credential
misconfiguration, orphaned-blueprint, disabled-with-access, and sponsor
accountability checks, plus the sign-in-activity enhancement to the stale
agent check (entraid_agent_009).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from entralint.checks.agent_identity.agent_blueprint_fic_misconfig.agent_blueprint_fic_misconfig import (  # noqa: E501
    AgentBlueprintFicMisconfig,
)
from entralint.checks.agent_identity.agent_blueprint_multi_tenant.agent_blueprint_multi_tenant import (  # noqa: E501
    AgentBlueprintMultiTenant,
)
from entralint.checks.agent_identity.agent_delegated_high_privilege.agent_delegated_high_privilege import (  # noqa: E501
    AgentDelegatedHighPrivilege,
)
from entralint.checks.agent_identity.agent_disabled_with_access.agent_disabled_with_access import (
    AgentDisabledWithAccess,
)
from entralint.checks.agent_identity.agent_no_sponsor.agent_no_sponsor import (
    AgentNoSponsor,
)
from entralint.checks.agent_identity.agent_orphaned_blueprint.agent_orphaned_blueprint import (
    AgentOrphanedBlueprint,
)
from entralint.checks.agent_identity.agent_stale_credentials.agent_stale_credentials import (
    STALE_DAYS,
    AgentStaleCredentials,
)
from entralint.core.check import Status
from entralint.core.context import TenantContext
from entralint.core.models import (
    AgentIdentity,
    AgentIdentityBlueprint,
    AppRoleAssignment,
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
    return AgentIdentityBlueprint(id=id, display_name=display_name, **kwargs)


def _ara(app_role_id: str = "role-1", **kwargs) -> AppRoleAssignment:
    return AppRoleAssignment(
        id=f"ara-{app_role_id}",
        app_role_id=app_role_id,
        principal_id="ag-1",
        principal_display_name="TestAgent",
        **kwargs,
    )


def _grant(scope: str, **kwargs) -> dict:
    return {"scope": scope, "consentType": "AllPrincipals", **kwargs}


# ---------------------------------------------------------------
# agent_013 — Delegated high-privilege scopes
# ---------------------------------------------------------------


class TestAgentDelegatedHighPrivilege:
    def test_pass_no_agents(self):
        findings = AgentDelegatedHighPrivilege().execute(_ctx())
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    def test_pass_low_risk_scope(self):
        agent = _agent(oauth2_permission_grants=[_grant("User.Read")])
        findings = AgentDelegatedHighPrivilege().execute(
            _ctx(agent_identities=[agent])
        )
        assert findings[0].status == Status.PASS

    def test_fail_high_risk_scope(self):
        agent = _agent(
            oauth2_permission_grants=[_grant("User.Read Mail.ReadWrite")]
        )
        findings = AgentDelegatedHighPrivilege().execute(
            _ctx(agent_identities=[agent])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
        assert "mail.readwrite" in findings[0].description.lower()

    def test_fail_case_insensitive_and_multiple(self):
        agent = _agent(
            oauth2_permission_grants=[
                _grant("FILES.READWRITE.ALL"),
                _grant("Directory.AccessAsUser.All"),
            ]
        )
        findings = AgentDelegatedHighPrivilege().execute(
            _ctx(agent_identities=[agent])
        )
        assert findings[0].status == Status.FAIL
        desc = findings[0].description.lower()
        assert "files.readwrite.all" in desc
        assert "directory.accessasuser.all" in desc

    def test_handles_empty_scope(self):
        agent = _agent(oauth2_permission_grants=[{"consentType": "Principal"}])
        findings = AgentDelegatedHighPrivilege().execute(
            _ctx(agent_identities=[agent])
        )
        assert findings[0].status == Status.PASS


# ---------------------------------------------------------------
# agent_014 — Multi-tenant blueprint
# ---------------------------------------------------------------


class TestAgentBlueprintMultiTenant:
    def test_pass_no_blueprints(self):
        findings = AgentBlueprintMultiTenant().execute(_ctx())
        assert findings[0].status == Status.PASS

    def test_pass_single_tenant(self):
        bp = _blueprint(sign_in_audience="AzureADMyOrg")
        findings = AgentBlueprintMultiTenant().execute(
            _ctx(agent_identity_blueprints=[bp])
        )
        assert findings[0].status == Status.PASS

    def test_fail_multi_tenant(self):
        bp = _blueprint(sign_in_audience="AzureADMultipleOrgs")
        findings = AgentBlueprintMultiTenant().execute(
            _ctx(agent_identity_blueprints=[bp])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL

    def test_fail_personal_account(self):
        bp = _blueprint(
            sign_in_audience="AzureADandPersonalMicrosoftAccount"
        )
        findings = AgentBlueprintMultiTenant().execute(
            _ctx(agent_identity_blueprints=[bp])
        )
        assert findings[0].status == Status.FAIL

    def test_pass_empty_audience(self):
        bp = _blueprint(sign_in_audience="")
        findings = AgentBlueprintMultiTenant().execute(
            _ctx(agent_identity_blueprints=[bp])
        )
        assert findings[0].status == Status.PASS


# ---------------------------------------------------------------
# agent_015 — Federated credential misconfiguration
# ---------------------------------------------------------------


def _fic(
    name: str = "fic-1",
    subject: str = "repo:contoso/app:ref:refs/heads/main",
    issuer: str = "https://token.actions.githubusercontent.com",
    audiences: list[str] | None = None,
) -> dict:
    return {
        "name": name,
        "subject": subject,
        "issuer": issuer,
        "audiences": audiences
        if audiences is not None
        else ["api://AzureADTokenExchange"],
    }


class TestAgentBlueprintFicMisconfig:
    def test_pass_no_blueprints(self):
        findings = AgentBlueprintFicMisconfig().execute(_ctx())
        assert findings[0].status == Status.PASS

    def test_pass_well_configured(self):
        bp = _blueprint(federated_identity_credentials=[_fic()])
        findings = AgentBlueprintFicMisconfig().execute(
            _ctx(agent_identity_blueprints=[bp])
        )
        assert findings[0].status == Status.PASS

    def test_fail_wildcard_subject(self):
        bp = _blueprint(federated_identity_credentials=[_fic(subject="*")])
        findings = AgentBlueprintFicMisconfig().execute(
            _ctx(agent_identity_blueprints=[bp])
        )
        assert findings[0].status == Status.FAIL
        assert "subject" in findings[0].description.lower()

    def test_fail_empty_subject(self):
        bp = _blueprint(federated_identity_credentials=[_fic(subject="")])
        findings = AgentBlueprintFicMisconfig().execute(
            _ctx(agent_identity_blueprints=[bp])
        )
        assert findings[0].status == Status.FAIL

    def test_fail_non_https_issuer(self):
        bp = _blueprint(
            federated_identity_credentials=[
                _fic(issuer="http://insecure.example.com")
            ]
        )
        findings = AgentBlueprintFicMisconfig().execute(
            _ctx(agent_identity_blueprints=[bp])
        )
        assert findings[0].status == Status.FAIL
        assert "issuer" in findings[0].description.lower()

    def test_fail_missing_audience(self):
        bp = _blueprint(
            federated_identity_credentials=[_fic(audiences=[])]
        )
        findings = AgentBlueprintFicMisconfig().execute(
            _ctx(agent_identity_blueprints=[bp])
        )
        assert findings[0].status == Status.FAIL
        assert "audience" in findings[0].description.lower()

    def test_fail_wrong_audience(self):
        bp = _blueprint(
            federated_identity_credentials=[
                _fic(audiences=["api://something-else"])
            ]
        )
        findings = AgentBlueprintFicMisconfig().execute(
            _ctx(agent_identity_blueprints=[bp])
        )
        assert findings[0].status == Status.FAIL


# ---------------------------------------------------------------
# agent_016 — Orphaned blueprint reference
# ---------------------------------------------------------------


class TestAgentOrphanedBlueprint:
    def test_skip_no_blueprints(self):
        agent = _agent(agent_identity_blueprint_id="bp-1")
        findings = AgentOrphanedBlueprint().execute(
            _ctx(agent_identities=[agent])
        )
        assert findings[0].status == Status.SKIPPED_DEPENDENCY

    def test_pass_matching_blueprint(self):
        bp = _blueprint(id="bp-1")
        agent = _agent(agent_identity_blueprint_id="bp-1")
        findings = AgentOrphanedBlueprint().execute(
            _ctx(agent_identities=[agent], agent_identity_blueprints=[bp])
        )
        assert findings[0].status == Status.PASS

    def test_pass_matching_by_app_id(self):
        bp = _blueprint(id="bp-obj-1", app_id="app-123")
        agent = _agent(agent_identity_blueprint_id="app-123")
        findings = AgentOrphanedBlueprint().execute(
            _ctx(agent_identities=[agent], agent_identity_blueprints=[bp])
        )
        assert findings[0].status == Status.PASS

    def test_fail_dangling_reference(self):
        bp = _blueprint(id="bp-1")
        agent = _agent(agent_identity_blueprint_id="bp-does-not-exist")
        findings = AgentOrphanedBlueprint().execute(
            _ctx(agent_identities=[agent], agent_identity_blueprints=[bp])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL

    def test_pass_agent_without_blueprint_ref(self):
        bp = _blueprint(id="bp-1")
        agent = _agent(agent_identity_blueprint_id=None)
        findings = AgentOrphanedBlueprint().execute(
            _ctx(agent_identities=[agent], agent_identity_blueprints=[bp])
        )
        assert findings[0].status == Status.PASS


# ---------------------------------------------------------------
# agent_017 — Disabled agent retaining access
# ---------------------------------------------------------------


class TestAgentDisabledWithAccess:
    def test_pass_no_agents(self):
        findings = AgentDisabledWithAccess().execute(_ctx())
        assert findings[0].status == Status.PASS

    def test_pass_enabled_with_access(self):
        agent = _agent(account_enabled=True, app_role_assignments=[_ara()])
        findings = AgentDisabledWithAccess().execute(
            _ctx(agent_identities=[agent])
        )
        assert findings[0].status == Status.PASS

    def test_pass_disabled_no_access(self):
        agent = _agent(account_enabled=False)
        findings = AgentDisabledWithAccess().execute(
            _ctx(agent_identities=[agent])
        )
        assert findings[0].status == Status.PASS

    def test_fail_disabled_with_app_roles(self):
        agent = _agent(account_enabled=False, app_role_assignments=[_ara()])
        findings = AgentDisabledWithAccess().execute(
            _ctx(agent_identities=[agent])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
        assert "app role" in findings[0].description.lower()

    def test_fail_disabled_with_grants(self):
        agent = _agent(
            account_enabled=False,
            oauth2_permission_grants=[_grant("Mail.Read")],
        )
        findings = AgentDisabledWithAccess().execute(
            _ctx(agent_identities=[agent])
        )
        assert findings[0].status == Status.FAIL
        assert "delegated grant" in findings[0].description.lower()


# ---------------------------------------------------------------
# agent_018 — Sponsor accountability
# ---------------------------------------------------------------


class TestAgentNoSponsor:
    def test_pass_no_agents_or_blueprints(self):
        findings = AgentNoSponsor().execute(_ctx())
        assert findings[0].status == Status.PASS

    def test_pass_agent_with_sponsor(self):
        agent = _agent(sponsors=[{"id": "user-1"}])
        findings = AgentNoSponsor().execute(_ctx(agent_identities=[agent]))
        assert findings[0].status == Status.PASS

    def test_fail_agent_without_sponsor(self):
        agent = _agent(owners=[{"id": "app-1"}], sponsors=[])
        findings = AgentNoSponsor().execute(_ctx(agent_identities=[agent]))
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL

    def test_fail_blueprint_without_sponsor(self):
        bp = _blueprint(sponsors=[])
        findings = AgentNoSponsor().execute(
            _ctx(agent_identity_blueprints=[bp])
        )
        assert findings[0].status == Status.FAIL

    def test_pass_blueprint_with_sponsor(self):
        bp = _blueprint(sponsors=[{"id": "user-1"}])
        findings = AgentNoSponsor().execute(
            _ctx(agent_identity_blueprints=[bp])
        )
        assert findings[0].status == Status.PASS


# ---------------------------------------------------------------
# agent_009 — Stale check sign-in-activity enhancement
# ---------------------------------------------------------------


class TestAgentStaleSignInActivity:
    def test_fail_stale_by_sign_in(self):
        recent_created = (
            datetime.now(tz=UTC) - timedelta(days=5)
        ).isoformat()
        old_sign_in = (
            datetime.now(tz=UTC) - timedelta(days=STALE_DAYS + 10)
        ).isoformat()
        agent = _agent(
            created_date_time=recent_created,
            sign_in_activity={"lastSignInDateTime": old_sign_in},
        )
        findings = AgentStaleCredentials().execute(
            _ctx(agent_identities=[agent])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
        assert "no sign-in" in findings[0].title.lower()

    def test_pass_recent_sign_in_old_creation(self):
        old_created = (
            datetime.now(tz=UTC) - timedelta(days=STALE_DAYS + 100)
        ).isoformat()
        recent_sign_in = (
            datetime.now(tz=UTC) - timedelta(days=3)
        ).isoformat()
        agent = _agent(
            created_date_time=old_created,
            sign_in_activity={"lastSignInDateTime": recent_sign_in},
        )
        findings = AgentStaleCredentials().execute(
            _ctx(agent_identities=[agent])
        )
        assert findings[0].status == Status.PASS

    def test_non_interactive_sign_in_counts(self):
        old_created = (
            datetime.now(tz=UTC) - timedelta(days=STALE_DAYS + 100)
        ).isoformat()
        recent_ni = (
            datetime.now(tz=UTC) - timedelta(days=2)
        ).isoformat()
        agent = _agent(
            created_date_time=old_created,
            sign_in_activity={
                "lastNonInteractiveSignInDateTime": recent_ni
            },
        )
        findings = AgentStaleCredentials().execute(
            _ctx(agent_identities=[agent])
        )
        assert findings[0].status == Status.PASS

    def test_fallback_to_creation_when_no_activity(self):
        old_created = (
            datetime.now(tz=UTC) - timedelta(days=STALE_DAYS + 1)
        ).isoformat()
        agent = _agent(created_date_time=old_created, sign_in_activity=None)
        findings = AgentStaleCredentials().execute(
            _ctx(agent_identities=[agent])
        )
        assert findings[0].status == Status.FAIL
        assert "days old" in findings[0].title
