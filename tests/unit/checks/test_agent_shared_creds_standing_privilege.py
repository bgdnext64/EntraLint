"""Tests for agent identity checks entraid_agent_019 and entraid_agent_020.

Covers:
- ``agent_shared_credentials`` (019): certificate thumbprint reuse across
  agent identities / blueprints.
- ``agent_standing_privilege`` (020): agent identities holding permanent
  (standing) privileged directory-role assignments.

PIM-eligible (just-in-time) assignments require Microsoft Entra ID P2, which
is not available in the test tenant. The standing-privilege check therefore
only reads active role assignments, which these tests exercise directly.
"""

from __future__ import annotations

from entralint.checks.agent_identity.agent_shared_credentials.agent_shared_credentials import (
    AgentSharedCredentials,
)
from entralint.checks.agent_identity.agent_standing_privilege.agent_standing_privilege import (
    PRIVILEGED_ROLE_IDS,
    AgentStandingPrivilege,
)
from entralint.core.check import Status
from entralint.core.context import TenantContext
from entralint.core.models import (
    AgentIdentity,
    AgentIdentityBlueprint,
    AgentIdentityBlueprintPrincipal,
    DirectoryRoleAssignment,
    KeyCredential,
)

_GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"
_NON_PRIVILEGED_ROLE = "88d8e3e3-8f55-4a1e-953a-9b9898b8876b"  # Reports Reader


def _ctx(**kwargs) -> TenantContext:
    return TenantContext(**kwargs)


def _cert(thumbprint: str | None) -> KeyCredential:
    return KeyCredential(
        key_id=f"key-{thumbprint}",
        credential_type="AsymmetricX509Cert",
        custom_key_identifier=thumbprint,
    )


def _agent(id: str, display_name: str, **kwargs) -> AgentIdentity:
    return AgentIdentity(id=id, display_name=display_name, **kwargs)


def _blueprint(id: str, display_name: str, **kwargs) -> AgentIdentityBlueprint:
    return AgentIdentityBlueprint(id=id, display_name=display_name, **kwargs)


def _bpp(
    id: str, display_name: str, **kwargs
) -> AgentIdentityBlueprintPrincipal:
    return AgentIdentityBlueprintPrincipal(
        id=id, display_name=display_name, **kwargs
    )


def _assignment(principal_id: str, role_definition_id: str) -> DirectoryRoleAssignment:
    return DirectoryRoleAssignment(
        id=f"ra-{principal_id}",
        principal_id=principal_id,
        role_definition_id=role_definition_id,
    )


# ---------------------------------------------------------------
# entraid_agent_019 — Shared credentials
# ---------------------------------------------------------------


class TestAgentSharedCredentials:
    def test_pass_no_agents(self):
        findings = AgentSharedCredentials().execute(_ctx())
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    def test_pass_unique_certs(self):
        agents = [
            _agent("ag-1", "Alpha", key_credentials=[_cert("THUMB-A")]),
            _agent("ag-2", "Bravo", key_credentials=[_cert("THUMB-B")]),
        ]
        findings = AgentSharedCredentials().execute(
            _ctx(agent_identities=agents)
        )
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    def test_fail_shared_cert_across_two_agents(self):
        agents = [
            _agent("ag-1", "Alpha", key_credentials=[_cert("SHARED")]),
            _agent("ag-2", "Bravo", key_credentials=[_cert("SHARED")]),
        ]
        findings = AgentSharedCredentials().execute(
            _ctx(agent_identities=agents)
        )
        assert len(findings) == 1
        finding = findings[0]
        assert finding.status == Status.FAIL
        assert finding.resource_id == "SHARED"
        assert len(finding.raw_data["owners"]) == 2
        assert "Alpha" in finding.title and "Bravo" in finding.title

    def test_fail_shared_cert_agent_and_blueprint(self):
        findings = AgentSharedCredentials().execute(
            _ctx(
                agent_identities=[
                    _agent("ag-1", "Alpha", key_credentials=[_cert("X")])
                ],
                agent_identity_blueprints=[
                    _blueprint("bp-1", "Blue", key_credentials=[_cert("X")])
                ],
            )
        )
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
        kinds = {o["type"] for o in findings[0].raw_data["owners"]}
        assert kinds == {"AgentIdentity", "AgentIdentityBlueprint"}

    def test_pass_same_object_lists_cert_twice(self):
        # A single agent registering the same thumbprint twice is not a
        # cross-agent share and must not be flagged.
        agent = _agent(
            "ag-1", "Alpha", key_credentials=[_cert("DUP"), _cert("DUP")]
        )
        findings = AgentSharedCredentials().execute(
            _ctx(agent_identities=[agent])
        )
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    def test_ignores_creds_without_thumbprint(self):
        agents = [
            _agent("ag-1", "Alpha", key_credentials=[_cert(None)]),
            _agent("ag-2", "Bravo", key_credentials=[_cert(None)]),
        ]
        findings = AgentSharedCredentials().execute(
            _ctx(agent_identities=agents)
        )
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    def test_fail_three_way_share(self):
        agents = [
            _agent("ag-1", "Alpha", key_credentials=[_cert("S")]),
            _agent("ag-2", "Bravo", key_credentials=[_cert("S")]),
            _agent("ag-3", "Charlie", key_credentials=[_cert("S")]),
        ]
        findings = AgentSharedCredentials().execute(
            _ctx(agent_identities=agents)
        )
        assert findings[0].status == Status.FAIL
        assert len(findings[0].raw_data["owners"]) == 3


# ---------------------------------------------------------------
# entraid_agent_020 — Standing privileged roles
# ---------------------------------------------------------------


class TestAgentStandingPrivilege:
    def test_pass_no_agents(self):
        findings = AgentStandingPrivilege().execute(_ctx())
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    def test_pass_agent_without_privileged_role(self):
        findings = AgentStandingPrivilege().execute(
            _ctx(
                agent_identities=[_agent("ag-1", "Alpha")],
                role_assignments=[_assignment("ag-1", _NON_PRIVILEGED_ROLE)],
            )
        )
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    def test_fail_agent_with_global_admin(self):
        findings = AgentStandingPrivilege().execute(
            _ctx(
                agent_identities=[_agent("ag-1", "Alpha")],
                role_assignments=[_assignment("ag-1", _GLOBAL_ADMIN)],
            )
        )
        assert len(findings) == 1
        finding = findings[0]
        assert finding.status == Status.FAIL
        assert finding.resource_id == "ag-1"
        assert "Global Administrator" in finding.title
        assert finding.raw_data["role_name"] == "Global Administrator"

    def test_pass_privileged_role_held_by_non_agent(self):
        # A privileged assignment to a principal that is not an agent
        # identity is out of scope for this check.
        findings = AgentStandingPrivilege().execute(
            _ctx(
                agent_identities=[_agent("ag-1", "Alpha")],
                role_assignments=[_assignment("user-99", _GLOBAL_ADMIN)],
            )
        )
        assert len(findings) == 1
        assert findings[0].status == Status.PASS

    def test_fail_blueprint_principal_standing_role(self):
        findings = AgentStandingPrivilege().execute(
            _ctx(
                agent_identity_blueprint_principals=[
                    _bpp("bpp-1", "PrincipalOne")
                ],
                role_assignments=[_assignment("bpp-1", _GLOBAL_ADMIN)],
            )
        )
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL
        assert findings[0].resource_id == "bpp-1"

    def test_fail_multiple_agents_multiple_findings(self):
        findings = AgentStandingPrivilege().execute(
            _ctx(
                agent_identities=[
                    _agent("ag-1", "Alpha"),
                    _agent("ag-2", "Bravo"),
                ],
                role_assignments=[
                    _assignment("ag-1", _GLOBAL_ADMIN),
                    _assignment("ag-2", _GLOBAL_ADMIN),
                ],
            )
        )
        assert len(findings) == 2
        assert all(f.status == Status.FAIL for f in findings)

    def test_global_admin_id_is_recognized(self):
        assert PRIVILEGED_ROLE_IDS[_GLOBAL_ADMIN] == "Global Administrator"
