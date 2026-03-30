"""Check: Detect service principals with privileged directory roles."""

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
    Path(__file__).parent / "role_sp_directory_roles.metadata.json"
)

_PRIVILEGED_ROLE_IDS = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
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


class RoleSpDirectoryRoles(BaseCheck):
    """Flags service principals holding privileged directory roles."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        sp_ids = {sp.id for sp in context.service_principals}
        findings: list[Finding] = []

        for assignment in context.role_assignments:
            role_name = _PRIVILEGED_ROLE_IDS.get(
                assignment.role_definition_id
            )
            if role_name is None:
                continue

            # Only flag if the principal is a service principal
            if assignment.principal_id not in sp_ids:
                continue

            principal_name = (
                assignment.principal.get(
                    "displayName", assignment.principal_id
                )
                if assignment.principal
                else assignment.principal_id
            )
            findings.append(
                Finding(
                    check_id=self.metadata.check_id,
                    status=Status.FAIL,
                    severity=self.metadata.severity,
                    resource_type=self.metadata.resource_type,
                    resource_id=assignment.principal_id,
                    title=(
                        f"SP has {role_name} role: {principal_name}"
                    ),
                    remediation=self.metadata.remediation.recommendation,
                )
            )

        if not findings:
            findings.append(
                Finding(
                    check_id=self.metadata.check_id,
                    status=Status.PASS,
                    severity=self.metadata.severity,
                    title="No SPs with privileged directory roles",
                )
            )

        return findings
