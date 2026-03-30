"""Check: Detect non-admin users owning apps with high-privilege permissions."""

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
    Path(__file__).parent / "app_priv_owner_escalation.metadata.json"
)

# Well-known high-privilege role template IDs
_ADMIN_ROLE_IDS = {
    "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Administrator
    "158c047a-c907-4556-b7ef-446551a6b5f7",  # Cloud Application Admin
    "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",  # Privileged Authentication Admin
    "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
}

# Dangerous Graph API permission IDs (app-only)
_DANGEROUS_PERMS = {
    "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8",  # RoleManagement.ReadWrite.All
    "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9",  # Application.ReadWrite.All
    "06b708a9-e830-4db3-a914-8e69da51d44f",  # AppRoleAssignment.ReadWrite.All
    "19dbc75e-c2e2-444c-a770-ec596d67c1e0",  # Directory.ReadWrite.All
    "e1fe6dd8-ba31-4d61-89e7-88639da4683d",  # User.ReadWrite.All
    "810c84a8-4a9e-49e6-bf7d-12d183f40d01",  # Mail.Read (app)
    "e2a3a72e-5f79-4c64-b1b1-878b674786c9",  # Mail.ReadWrite (app)
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


class AppPrivOwnerEscalation(BaseCheck):
    """Flags apps with high-privilege perms owned by non-admin users."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        # Build set of admin principal IDs
        admin_ids: set[str] = set()
        for ra in context.role_assignments:
            if ra.role_definition_id in _ADMIN_ROLE_IDS:
                admin_ids.add(ra.principal_id)

        findings: list[Finding] = []
        for app in context.applications:
            if not self._has_dangerous_perms(app):
                continue

            non_admin_owners = []
            for owner in app.owners or []:
                owner_id = owner.get("id", "")
                if owner_id and owner_id not in admin_ids:
                    name = owner.get("displayName", owner_id)
                    non_admin_owners.append(name)

            if non_admin_owners:
                findings.append(Finding(
                    check_id=self.metadata.check_id,
                    check_version=self.metadata.check_version,
                    status=Status.FAIL,
                    severity=self.metadata.severity,
                    resource_type=self.metadata.resource_type,
                    resource_id=app.id,
                    title=(
                        f"Non-admin owns privileged app: "
                        f"{app.display_name}"
                    ),
                    description=(
                        f"App '{app.display_name}' requests high-"
                        f"privilege permissions and is owned by non-"
                        f"admin user(s): "
                        f"{', '.join(non_admin_owners)}. This creates "
                        "a privilege escalation path."
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
                resource_id="tenant",
                title="No privilege escalation via app owners",
                description=(
                    "No applications with high-privilege permissions "
                    "are owned by non-admin users."
                ),
                remediation="",
            ))

        return findings

    @staticmethod
    def _has_dangerous_perms(app) -> bool:
        """Check if an app requests any dangerous permissions."""
        for rra in app.required_resource_access or []:
            for access in rra.resource_access or []:
                if access.id in _DANGEROUS_PERMS:
                    return True
        return False
