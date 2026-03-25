"""Check: Ensure fewer than 5 users have the Global Administrator role."""

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
    / "role_excessive_global_admins.metadata.json"
)

# Global Administrator role definition ID is fixed across all tenants.
GLOBAL_ADMIN_ROLE_TEMPLATE_ID = "62e90394-69f5-4237-9190-012177145e10"

MAX_GLOBAL_ADMINS = 4


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


class RoleExcessiveGlobalAdmins(BaseCheck):
    """Flags tenants with more than MAX_GLOBAL_ADMINS Global Administrators."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        ga_assignments = [
            a for a in context.role_assignments
            if a.role_definition_id == GLOBAL_ADMIN_ROLE_TEMPLATE_ID
        ]

        count = len(ga_assignments)

        if count > MAX_GLOBAL_ADMINS:
            principal_names = []
            for a in ga_assignments:
                name = (
                    a.principal.get("displayName", a.principal_id)
                    if a.principal
                    else a.principal_id
                )
                principal_names.append(name)

            return [Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.FAIL,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id="Global Administrator",
                title=(
                    f"Excessive Global Admins: {count} "
                    f"(max recommended: {MAX_GLOBAL_ADMINS})"
                ),
                description=(
                    f"Found {count} Global Administrator assignments "
                    f"(recommended max: {MAX_GLOBAL_ADMINS}). "
                    f"Principals: {', '.join(principal_names[:10])}"
                ),
                remediation=self.metadata.remediation.recommendation,
            )]

        return [Finding(
            check_id=self.metadata.check_id,
            check_version=self.metadata.check_version,
            status=Status.PASS,
            severity=self.metadata.severity,
            resource_type=self.metadata.resource_type,
            resource_id="Global Administrator",
            title=(
                f"Global Admin count within limits: {count} "
                f"(max: {MAX_GLOBAL_ADMINS})"
            ),
            description=(
                f"Found {count} Global Administrator assignment(s), "
                f"which is within the recommended maximum of "
                f"{MAX_GLOBAL_ADMINS}."
            ),
        )]
