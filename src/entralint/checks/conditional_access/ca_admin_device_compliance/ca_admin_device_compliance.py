"""Check: Ensure managed device required for admin access."""

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
    Path(__file__).parent / "ca_admin_device_compliance.metadata.json"
)

# Well-known admin role template IDs.
_ADMIN_ROLE_IDS = {
    "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
    "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Admin
    "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Admin
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Admin
    "158c047a-c907-4556-b7ef-446551a6b5f7",  # Cloud App Admin
    "fe930be7-5e62-47db-91af-98c3a49a38b1",  # User Admin
}


def _load_metadata() -> CheckMetadata:
    raw = json.loads(_METADATA_PATH.read_text(encoding="utf-8"))
    r = raw["Remediation"]
    return CheckMetadata(
        check_id=raw["CheckID"],
        check_version=raw["CheckVersion"],
        check_title=raw["CheckTitle"],
        service_name=raw["ServiceName"],
        severity=Severity(raw["Severity"]),
        resource_type=raw["ResourceType"],
        description=raw["Description"],
        risk=raw["Risk"],
        remediation=Remediation(recommendation=r["Recommendation"], url=r.get("Url", "")),
        frameworks=raw["Frameworks"],
        graph_api_endpoints=raw["GraphAPIEndpoints"],
        required_permissions=raw["RequiredPermissions"],
        required_license=raw.get("RequiredLicense"),
        depends_on=raw.get("DependsOn", []),
        source_notes=raw.get("SourceNotes", ""),
    )


class CaAdminDeviceCompliance(BaseCheck):
    """Checks for device compliance requirement for admin roles."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        for policy in context.conditional_access_policies:
            if policy.state != "enabled":
                continue

            # Check if the policy targets admin roles
            include_roles = set(policy.conditions.users.include_roles)
            targets_admins = bool(include_roles & _ADMIN_ROLE_IDS)

            if not targets_admins:
                continue

            gc = policy.grant_controls
            if gc is None:
                continue

            device_controls = {
                "compliantDevice",
                "domainJoinedDevice",
            }
            if device_controls & set(gc.built_in_controls):
                return [
                    Finding(
                        check_id=self.metadata.check_id,
                        status=Status.PASS,
                        severity=self.metadata.severity,
                        title=(
                            "Device compliance required for admins"
                        ),
                        description=(
                            f"Policy '{policy.display_name}' requires "
                            "a compliant or managed device for admin roles."
                        ),
                    )
                ]

        return [
            Finding(
                check_id=self.metadata.check_id,
                status=Status.FAIL,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                title="No managed device requirement for admins",
                description=(
                    "No enabled CA policy requires a compliant or "
                    "hybrid-joined device for privileged admin roles."
                ),
                remediation=self.metadata.remediation.recommendation,
            )
        ]
