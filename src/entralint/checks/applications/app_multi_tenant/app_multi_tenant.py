"""Check: Review multi-tenant app registrations."""

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

_METADATA_PATH = Path(__file__).parent / "app_multi_tenant.metadata.json"

MULTI_TENANT_AUDIENCES = {
    "AzureADMultipleOrgs",
    "AzureADandPersonalMicrosoftAccount",
    "PersonalMicrosoftAccount",
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


class AppMultiTenant(BaseCheck):
    """Flags app registrations configured for multi-tenant access."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        findings: list[Finding] = []

        for app in context.applications:
            if app.sign_in_audience not in MULTI_TENANT_AUDIENCES:
                continue

            findings.append(Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.FAIL,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id=app.app_id,
                title=f"Multi-tenant app: {app.display_name}",
                description=(
                    f"App '{app.display_name}' accepts sign-ins from "
                    f"audience '{app.sign_in_audience}'. Verify this is "
                    f"intentional and tenant validation is implemented."
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
                title="No multi-tenant app registrations found",
                description=(
                    "All app registrations are configured for "
                    "single-tenant (AzureADMyOrg) access."
                ),
            ))

        return findings
