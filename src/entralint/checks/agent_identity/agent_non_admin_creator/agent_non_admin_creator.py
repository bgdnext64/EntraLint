"""Check: Ensure agent identities are created by authorized apps."""

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
    Path(__file__).parent / "agent_non_admin_creator.metadata.json"
)

# Well-known Microsoft first-party applications commonly used to create
# agent identities through interactive, self-service tooling. Creation by
# these apps reflects expected administrative activity (an admin ran Graph
# PowerShell, the Azure CLI, etc.) rather than a rogue third-party actor.
# These are reported at LOW severity as a governance signal instead of being
# treated as an unknown external creator.
MICROSOFT_FIRST_PARTY_APPS: dict[str, str] = {
    "14d82eec-204b-4c2f-b7e8-296a70dab67e": "Microsoft Graph Command Line Tools",
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46": "Azure CLI",
    "1950a258-227b-4e31-a9cf-717495945fc2": "Azure PowerShell",
    "de8bc8b5-d9f9-48b1-a8ad-b748da725064": "Graph Explorer",
    "c44b4083-3bb0-49c1-b47d-974e53cbdf3c": "Azure Portal",
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


class AgentNonAdminCreator(BaseCheck):
    """Flags agents created by unrecognized applications."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        findings: list[Finding] = []

        # Apps registered in this tenant are considered governed creators.
        known_app_ids = {app.app_id for app in context.applications}

        # Resolve creator app IDs to display names using the tenant's
        # service principals. This covers Microsoft first-party apps that
        # have a service principal in the tenant but no local app
        # registration, so findings name the actual application.
        sp_names = {
            sp.app_id: sp.display_name
            for sp in context.service_principals
            if sp.app_id
        }

        for agent in context.agent_identities:
            creator = agent.created_by_app_id
            if not creator or creator in known_app_ids:
                continue

            first_party_name = MICROSOFT_FIRST_PARTY_APPS.get(creator)
            creator_name = (
                first_party_name
                or sp_names.get(creator)
                or "unknown application"
            )
            raw_data = {
                "agent_id": agent.id,
                "agent_display_name": agent.display_name,
                "created_by_app_id": creator,
                "creator_display_name": creator_name,
                "creator_is_microsoft_first_party": first_party_name is not None,
            }

            if first_party_name is not None:
                findings.append(Finding(
                    check_id=self.metadata.check_id,
                    check_version=self.metadata.check_version,
                    status=Status.FAIL,
                    severity=Severity.LOW,
                    resource_type=self.metadata.resource_type,
                    resource_id=agent.id,
                    title=(
                        f"Agent '{agent.display_name}' created via "
                        f"self-service tooling '{first_party_name}' "
                        f"({creator})"
                    ),
                    description=(
                        f"Agent identity was created by the Microsoft "
                        f"first-party application '{first_party_name}' "
                        f"({creator}), which typically indicates "
                        f"self-service provisioning by an administrator "
                        f"rather than a governed process. Confirm the "
                        f"creation was intentional and tracked."
                    ),
                    remediation=self.metadata.remediation.recommendation,
                    raw_data=raw_data,
                ))
            else:
                findings.append(Finding(
                    check_id=self.metadata.check_id,
                    check_version=self.metadata.check_version,
                    status=Status.FAIL,
                    severity=self.metadata.severity,
                    resource_type=self.metadata.resource_type,
                    resource_id=agent.id,
                    title=(
                        f"Agent '{agent.display_name}' created by "
                        f"third-party app '{creator_name}' ({creator})"
                    ),
                    description=(
                        f"Agent identity was created by application "
                        f"'{creator_name}' ({creator}), which is neither "
                        f"registered in this tenant nor a recognized "
                        f"Microsoft first-party service. This may "
                        f"indicate unauthorized or unmonitored external "
                        f"provisioning."
                    ),
                    remediation=self.metadata.remediation.recommendation,
                    raw_data=raw_data,
                ))

        if not findings:
            findings.append(Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.PASS,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id="tenant-wide",
                title="All agents created by known applications",
            ))

        return findings
