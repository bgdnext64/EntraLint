"""Check: Ensure Privileged Role Administrator has no more than 2 assignments."""

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

_METADATA_PATH = Path(__file__).parent / "role_pra_excessive.metadata.json"

# Privileged Role Administrator role definition ID
PRA_ROLE_ID = "e8611ab8-c189-46e8-94e1-60213ab1f814"
MAX_PRA_ASSIGNMENTS = 2


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


class RolePraExcessive(BaseCheck):
    """Flags tenants with more than 2 Privileged Role Administrator assignments."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        if not context.role_assignments:
            return self.skip(
                "No role assignments available",
                status=Status.SKIPPED_PERMISSION,
            )

        pra_assignments = [
            ra for ra in context.role_assignments
            if ra.role_definition_id == PRA_ROLE_ID
        ]

        count = len(pra_assignments)
        if count > MAX_PRA_ASSIGNMENTS:
            names = [
                (ra.principal or {}).get("displayName", ra.principal_id)
                for ra in pra_assignments
            ]
            return [Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.FAIL,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id="Privileged Role Administrator",
                title=(
                    f"Privileged Role Administrator has"
                    f" {count} assignments"
                    f" (max {MAX_PRA_ASSIGNMENTS})"
                ),
                description=(
                    f"Found {count} Privileged Role Administrator assignments: "
                    f"{', '.join(names[:5])}{'...' if len(names) > 5 else ''}. "
                    f"Each PRA can assign any role including Global Admin."
                ),
                remediation=self.metadata.remediation.recommendation,
            )]

        return [Finding(
            check_id=self.metadata.check_id,
            check_version=self.metadata.check_version,
            status=Status.PASS,
            severity=self.metadata.severity,
            resource_type=self.metadata.resource_type,
            resource_id="Privileged Role Administrator",
            title=f"Privileged Role Administrator has {count} assignment(s)",
            description=(
                f"PRA assignment count ({count}) is within"
                f" the recommended maximum"
                f" of {MAX_PRA_ASSIGNMENTS}."
            ),
        )]
