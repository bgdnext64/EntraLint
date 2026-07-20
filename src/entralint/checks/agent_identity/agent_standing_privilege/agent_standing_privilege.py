"""Check: Detect agent identities holding standing privileged roles."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from entralint.core.check import (
    BaseCheck,
    CheckMetadata,
    Finding,
    Remediation,
    Severity,
    Status,
)

if TYPE_CHECKING:
    from entralint.core.context import TenantContext

_METADATA_PATH = (
    Path(__file__).parent / "agent_standing_privilege.metadata.json"
)

# High-privilege built-in directory role definition IDs (fixed across
# all tenants). A permanent assignment of any of these to an agent
# identity is a standing-privilege finding.
PRIVILEGED_ROLE_IDS = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "b0f54661-2d74-4c50-afa3-1ec803f12efe": "Billing Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
}


def _load_metadata() -> CheckMetadata:
    raw = json.loads(_METADATA_PATH.read_text(encoding="utf-8"))
    remediation_raw = raw["Remediation"]
    return CheckMetadata(
        check_id=raw["CheckID"],
        check_version=raw["CheckVersion"],
        check_title=raw["CheckTitle"],
        service_name=raw["ServiceName"],
        severity=Severity(raw["Severity"]),
        resource_type=raw["ResourceType"],
        description=raw["Description"],
        risk=raw["Risk"],
        remediation=Remediation(
            recommendation=remediation_raw["Recommendation"],
            url=remediation_raw.get("Url", ""),
        ),
        frameworks=raw["Frameworks"],
        graph_api_endpoints=raw["GraphAPIEndpoints"],
        required_permissions=raw["RequiredPermissions"],
        required_license=raw.get("RequiredLicense"),
        depends_on=raw.get("DependsOn", []),
        source_notes=raw.get("SourceNotes", ""),
    )


class AgentStandingPrivilege(BaseCheck):
    """Flags agent identities with permanent privileged role assignments."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        # Map every agent principal object id to a display name so we can
        # attribute role assignments and only flag agent-owned ones.
        agent_names: dict[str, str] = {}
        for agent in context.agent_identities:
            agent_names[agent.id] = agent.display_name or agent.id
        for principal in context.agent_identity_blueprint_principals:
            agent_names[principal.id] = principal.display_name or principal.id

        findings: list[Finding] = []

        for assignment in context.role_assignments:
            role_name = PRIVILEGED_ROLE_IDS.get(assignment.role_definition_id)
            if role_name is None:
                continue
            if assignment.principal_id not in agent_names:
                continue

            agent_name = agent_names[assignment.principal_id]
            findings.append(
                Finding(
                    check_id=self.metadata.check_id,
                    check_version=self.metadata.check_version,
                    status=Status.FAIL,
                    severity=self.metadata.severity,
                    resource_type=self.metadata.resource_type,
                    resource_id=assignment.principal_id,
                    title=(
                        f"Agent '{agent_name}' holds standing "
                        f"{role_name} role"
                    ),
                    description=(
                        f"Agent identity '{agent_name}' has a permanent "
                        f"{role_name} assignment. Standing privileged "
                        f"access should be replaced with a time-limited, "
                        f"just-in-time entitlement scoped to the task."
                    ),
                    remediation=self.metadata.remediation.recommendation,
                    raw_data={
                        "role_definition_id": assignment.role_definition_id,
                        "role_name": role_name,
                        "directory_scope_id": assignment.directory_scope_id,
                    },
                )
            )

        if not findings:
            findings.append(
                Finding(
                    check_id=self.metadata.check_id,
                    check_version=self.metadata.check_version,
                    status=Status.PASS,
                    severity=self.metadata.severity,
                    resource_type=self.metadata.resource_type,
                    resource_id="tenant-wide",
                    title="No agent identities hold standing privileged roles",
                )
            )

        return findings
