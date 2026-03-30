"""Check: Detect disabled user accounts with active role assignments."""

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

_METADATA_PATH = Path(__file__).parent / "user_disabled_with_roles.metadata.json"


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


class UserDisabledWithRoles(BaseCheck):
    """Flags disabled user accounts that still have directory role assignments."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        if not context.users or not context.role_assignments:
            return self.skip(
                "Users or role assignments not available",
                status=Status.SKIPPED_PERMISSION,
            )

        # Build set of disabled user IDs
        disabled_ids = {
            u.id for u in context.users if not u.account_enabled
        }
        disabled_names = {
            u.id: u.display_name or u.user_principal_name
            for u in context.users if not u.account_enabled
        }

        # Find role assignments for disabled users
        flagged: list[str] = []
        for ra in context.role_assignments:
            if ra.principal_id in disabled_ids:
                name = disabled_names.get(ra.principal_id, ra.principal_id)
                if name not in flagged:
                    flagged.append(name)

        if flagged:
            return [Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.FAIL,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id="tenant-wide",
                title=f"{len(flagged)} disabled user(s) with active role assignments",
                description=(
                    f"Found {len(flagged)} disabled accounts still assigned "
                    f"directory roles: "
                    f"{', '.join(flagged[:10])}{'...' if len(flagged) > 10 else ''}. "
                    f"These roles would be active immediately if accounts are re-enabled."
                ),
                remediation=self.metadata.remediation.recommendation,
            )]

        return [Finding(
            check_id=self.metadata.check_id,
            check_version=self.metadata.check_version,
            status=Status.PASS,
            severity=self.metadata.severity,
            resource_type=self.metadata.resource_type,
            resource_id="tenant-wide",
            title="No disabled accounts have role assignments",
            description=(
                "All disabled user accounts have had their"
                " directory role assignments removed."
            ),
        )]
