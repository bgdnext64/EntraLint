"""Check: Review cross-tenant inbound trust for external MFA claims."""

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

_METADATA_PATH = Path(__file__).parent / "org_cross_tenant_mfa_trust.metadata.json"


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


class OrgCrossTenantMfaTrust(BaseCheck):
    """Flags tenants that trust external MFA claims in cross-tenant access."""

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
        mfa_accepted = inbound_trust.get("isMfaAccepted", False)

        if mfa_accepted:
            return [Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.FAIL,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id="cross-tenant-default",
                title="Cross-tenant inbound policy trusts external MFA claims",
                description=(
                    "The default cross-tenant access policy trusts MFA claims "
                    "from external tenants. Your CA policies will accept MFA "
                    "performed in other organizations, which may have weaker "
                    "MFA requirements."
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
            title="Cross-tenant inbound policy does not trust external MFA",
            description=(
                "External MFA claims are not trusted by"
                " default. B2B users must satisfy your"
                " tenant's MFA requirements directly."
            ),
        )]
