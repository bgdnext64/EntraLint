"""Check: Ensure Application Administrator has no more than 5 assignments."""

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

_METADATA_PATH = Path(__file__).parent / "role_app_admin_excessive.metadata.json"

# Application Administrator role definition ID
APP_ADMIN_ROLE_ID = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"
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


class RoleAppAdminExcessive(BaseCheck):
    """Flags tenants with more than 5 Application Administrator assignments."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        if not context.role_assignments:
            return self.skip(
                "No role assignments available",
                status=Status.SKIPPED_PERMISSION,
            )

        app_admin = [
            ra for ra in context.role_assignments
            if ra.role_definition_id == APP_ADMIN_ROLE_ID
        ]

        count = len(app_admin)
        if count > MAX_ASSIGNMENTS:
            return [Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.FAIL,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id="Application Administrator",
                title=f"Application Administrator has {count} assignments (max {MAX_ASSIGNMENTS})",
                description=(
                    f"Found {count} Application Administrator assignments, "
                    f"exceeding the recommended maximum of {MAX_ASSIGNMENTS}. "
                    f"Each holder can manage credentials for any app registration."
                ),
                remediation=self.metadata.remediation.recommendation,
            )]

        return [Finding(
            check_id=self.metadata.check_id,
            check_version=self.metadata.check_version,
            status=Status.PASS,
            severity=self.metadata.severity,
            resource_type=self.metadata.resource_type,
            resource_id="Application Administrator",
            title=f"Application Administrator has {count} assignment(s)",
            description=(
                f"Application Administrator count ({count})"
                f" is within the recommended maximum"
                f" of {MAX_ASSIGNMENTS}."
            ),
        )]
