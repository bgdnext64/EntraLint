"""Check: Ensure no agent identity holds a blocked permission."""

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
    Path(__file__).parent / "agent_blocked_permission.metadata.json"
)

# Microsoft-blocked application permission GUIDs for agents.
BLOCKED_APP_ROLE_IDS: dict[str, str] = {
    "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9": "Application.ReadWrite.All",
    "18a4783c-866b-4cc7-a460-3d5e5662c884": "Application.ReadWrite.OwnedBy",
    "06b708a9-e830-4db3-a914-8e69da51d44f": "AppRoleAssignment.ReadWrite.All",
    "19dbc75e-c2e2-444c-a770-ec596d83d1bc": "Directory.ReadWrite.All",
    "cac88765-0581-4025-9725-5ebc13f729ee": "Directory.Write.Restricted",
    "8e8e4742-1d95-4f68-9d56-6ee75648c72a": "DelegatedPermissionGrant.ReadWrite.All",
    "01d4f6f4-da2b-4894-854e-4f7f5c868bd8": "Files.Read.All",
    "75359482-378d-4052-8f01-80520e7db3cd": "Files.ReadWrite.All",
    "62a82d76-70ea-41e2-9197-370581804d09": "Group.ReadWrite.All",
    "dbaae8cf-10b5-4b86-a4a1-f871c94c6a39": "GroupMember.ReadWrite.All",
    "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8": "RoleManagement.ReadWrite.Directory",
    "a82116e5-55eb-4c41-a434-62fe8a61c773": "Sites.FullControl.All",
    "883ea226-0bf2-4a8f-9f9d-92c9162a727d": "Sites.Manage.All",
    "332a536c-c7ef-4017-ab91-336970924f0d": "Sites.Read.All",
    "9492366f-7969-46a4-8d15-ed1a20078fff": "Sites.ReadWrite.All",
    "741f803b-c850-494e-b5df-cde7c675a1ca": "User.ReadWrite.All",
    "4d02b0cc-d90b-441f-8d51-76c291fac474": "User.DeleteRestore.All",
    "be1a4d56-c2d0-4448-8ec0-2238bbd75bba": "User.EnableDisableAccount.All",
    "09850681-111b-4a89-9571-53f363f37f4b": "UserAuthenticationMethod.ReadWrite.All",
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


class AgentBlockedPermission(BaseCheck):
    """Flags agents holding permissions from the blocked list."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        findings: list[Finding] = []

        for agent in context.agent_identities:
            blocked: list[str] = []
            for ara in agent.app_role_assignments:
                perm_name = BLOCKED_APP_ROLE_IDS.get(ara.app_role_id)
                if perm_name:
                    blocked.append(perm_name)

            if blocked:
                findings.append(Finding(
                    check_id=self.metadata.check_id,
                    check_version=self.metadata.check_version,
                    status=Status.FAIL,
                    severity=self.metadata.severity,
                    resource_type=self.metadata.resource_type,
                    resource_id=agent.id,
                    title=(
                        f"Agent '{agent.display_name}' holds "
                        f"blocked permission(s)"
                    ),
                    description=(
                        f"Agent identity holds {len(blocked)} "
                        f"permission(s) from the Microsoft blocked "
                        f"list: {', '.join(sorted(blocked))}."
                    ),
                    remediation=self.metadata.remediation.recommendation,
                ))

        if not findings:
            findings.append(Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.PASS,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id="tenant-wide",
                title="No agents hold blocked permissions",
            ))

        return findings
