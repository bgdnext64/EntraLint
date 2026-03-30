"""Check: Review cross-tenant inbound trust for external device compliance."""

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

_METADATA_PATH = Path(__file__).parent / "org_cross_tenant_device_trust.metadata.json"


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


class OrgCrossTenantDeviceTrust(BaseCheck):
    """Flags tenants that trust external device compliance claims."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        policy = context.cross_tenant_access_policy
        if not policy:
            return self.skip(
                "Cross-tenant access policy not available",
                status=Status.SKIPPED_PERMISSION,
            )

        inbound_trust = policy.get("inboundTrust", {})
        compliant = inbound_trust.get("isCompliantDeviceAccepted", False)
        hybrid = inbound_trust.get("isHybridAzureADJoinedDeviceAccepted", False)

        issues: list[str] = []
        if compliant:
            issues.append("compliant device")
        if hybrid:
            issues.append("hybrid Azure AD joined device")

        if issues:
            return [Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.FAIL,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id="cross-tenant-default",
                title=f"Cross-tenant inbound trusts external {' and '.join(issues)} claims",
                description=(
                    f"The default cross-tenant access policy trusts "
                    f"{' and '.join(issues)} claims from external tenants. "
                    f"Your CA device requirements may be bypassed by B2B users."
                ),
                remediation=self.metadata.remediation.recommendation,
            )]

        return [Finding(
            check_id=self.metadata.check_id,
            check_version=self.metadata.check_version,
            status=Status.PASS,
            severity=self.metadata.severity,
            resource_type=self.metadata.resource_type,
            resource_id="cross-tenant-default",
            title="Cross-tenant inbound policy does not trust external device claims",
            description=(
                "External device compliance and hybrid join"
                " claims are not trusted by default."
            ),
        )]
