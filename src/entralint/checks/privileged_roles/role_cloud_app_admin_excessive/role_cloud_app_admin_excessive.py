"""Check: Ensure Cloud Application Administrator has no more than 5 assignments."""

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

_METADATA_PATH = Path(__file__).parent / "role_cloud_app_admin_excessive.metadata.json"

# Cloud Application Administrator role definition ID
CLOUD_APP_ADMIN_ROLE_ID = "158c047a-c907-4556-b7ef-446551a6b5f7"
MAX_ASSIGNMENTS = 5


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


class RoleCloudAppAdminExcessive(BaseCheck):
    """Flags tenants with more than 5 Cloud Application Admin assignments."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        if not context.role_assignments:
            return self.skip(
                "No role assignments available",
                status=Status.SKIPPED_PERMISSION,
            )

        cloud_app_admin = [
            ra for ra in context.role_assignments
            if ra.role_definition_id == CLOUD_APP_ADMIN_ROLE_ID
        ]

        count = len(cloud_app_admin)
        if count > MAX_ASSIGNMENTS:
            return [Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.FAIL,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id="Cloud Application Administrator",
                title=(
                    f"Cloud Application Administrator has"
                    f" {count} assignments (max {MAX_ASSIGNMENTS})"
                ),
                description=(
                    f"Found {count} Cloud Application Administrator assignments, "
                    f"exceeding the recommended maximum of {MAX_ASSIGNMENTS}. "
                    f"Each holder can manage credentials for service principals."
                ),
                remediation=self.metadata.remediation.recommendation,
            )]

        return [Finding(
            check_id=self.metadata.check_id,
            check_version=self.metadata.check_version,
            status=Status.PASS,
            severity=self.metadata.severity,
            resource_type=self.metadata.resource_type,
            resource_id="Cloud Application Administrator",
            title=f"Cloud Application Administrator has {count} assignment(s)",
            description=(
                f"Cloud Application Administrator count"
                f" ({count}) is within the recommended"
                f" maximum of {MAX_ASSIGNMENTS}."
            ),
        )]
