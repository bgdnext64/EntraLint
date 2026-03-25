"""Check: Review SPs with high-privilege granted application permissions."""

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
    Path(__file__).parent
    / "sp_high_privilege_granted.metadata.json"
)

# High-privilege Microsoft Graph app role IDs (same GUIDs across all tenants).
HIGH_PRIVILEGE_ROLE_IDS: dict[str, str] = {
    "19dbc75e-c2e2-444c-a770-ec596d83d1bc": "Directory.ReadWrite.All",
    "62a82d76-70ea-41e2-9197-370581804d09": "Group.ReadWrite.All",
    "06b708a9-e830-4db3-a914-8e69da51d44f": "AppRoleAssignment.ReadWrite.All",
    "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8": "RoleManagement.ReadWrite.Directory",
    "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9": "Application.ReadWrite.All",
    "e2a3a72e-5f79-4c64-b1b1-878b674786c9": "Mail.ReadWrite",
    "b633e1c5-b582-4048-a93e-9f11b44c7e96": "Mail.Send",
    "741f803b-c850-494e-b5df-cde7c675a1ca": "User.ReadWrite.All",
    "75359482-378d-4052-8f01-80520e7db3cd": "Files.ReadWrite.All",
    "9492366f-7969-46a4-8d15-ed1a20078fff": "Sites.ReadWrite.All",
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


class SpHighPrivilegeGranted(BaseCheck):
    """Flags SPs with high-privilege granted application permissions."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        findings: list[Finding] = []

        # Group assignments by principal
        by_principal: dict[str, list[str]] = {}
        for ara in context.app_role_assignments:
            perm_name = HIGH_PRIVILEGE_ROLE_IDS.get(ara.app_role_id)
            if perm_name is None:
                continue
            key = ara.principal_display_name or ara.principal_id
            by_principal.setdefault(key, []).append(perm_name)

        for principal_name, perms in sorted(by_principal.items()):
            findings.append(Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.FAIL,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id=principal_name,
                title=(
                    f"High-privilege app permissions: "
                    f"{principal_name}"
                ),
                description=(
                    f"'{principal_name}' has {len(perms)} "
                    f"high-privilege granted permission(s): "
                    f"{', '.join(sorted(perms))}"
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
                title=(
                    "No SPs with high-privilege granted "
                    "application permissions"
                ),
                description=(
                    "No service principals have been granted "
                    "dangerous Microsoft Graph application roles."
                ),
            ))

        return findings
