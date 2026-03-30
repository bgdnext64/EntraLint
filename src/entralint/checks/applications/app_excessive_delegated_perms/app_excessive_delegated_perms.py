"""Check: Detect applications requesting excessive delegated permissions."""

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

_METADATA_PATH = Path(__file__).parent / "app_excessive_delegated_perms.metadata.json"

MAX_DELEGATED_SCOPES = 10
# Microsoft Graph app ID
GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"


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


class AppExcessiveDelegatedPerms(BaseCheck):
    """Flags apps requesting more than 10 delegated permissions."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        if not context.applications:
            return self.skip(
                "No applications available",
                status=Status.SKIPPED_PERMISSION,
            )

        findings: list[Finding] = []
        for app in context.applications:
            delegated_count = 0
            for rra in app.required_resource_access:
                for ra in rra.resource_access:
                    if ra.type == "Scope":
                        delegated_count += 1

            if delegated_count > MAX_DELEGATED_SCOPES:
                findings.append(Finding(
                    check_id=self.metadata.check_id,
                    check_version=self.metadata.check_version,
                    status=Status.FAIL,
                    severity=self.metadata.severity,
                    resource_type=self.metadata.resource_type,
                    resource_id=app.id,
                    title=f"{app.display_name}: {delegated_count} delegated permissions",
                    description=(
                        f"Application '{app.display_name}' requests "
                        f"{delegated_count} delegated permissions, exceeding "
                        f"the recommended maximum of {MAX_DELEGATED_SCOPES}. "
                        f"Review and remove unnecessary scopes."
                    ),
                    remediation=self.metadata.remediation.recommendation,
                ))

        if not findings:
            return [Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.PASS,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id="tenant-wide",
                title="No applications have excessive delegated permissions",
                description=(
                    f"All applications request {MAX_DELEGATED_SCOPES}"
                    " or fewer delegated scopes."
                ),
            )]

        return findings
