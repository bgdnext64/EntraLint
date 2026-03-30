"""Check: Review outbound cross-tenant access for unrestricted defaults."""

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
    Path(__file__).parent / "org_outbound_cross_tenant.metadata.json"
)


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


def _check_outbound_section(section: dict) -> bool:
    """Return True if the outbound section is unrestricted (all allowed)."""
    apps = section.get("applications", {})
    users = section.get("usersAndGroups", {})
    return (
        apps.get("accessType") == "allowed"
        and users.get("accessType") == "allowed"
    )


class OrgOutboundCrossTenant(BaseCheck):
    """Flags unrestricted outbound cross-tenant access defaults."""

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

        findings: list[Finding] = []
        b2b_collab = policy.get("b2bCollaborationOutbound", {})
        b2b_direct = policy.get("b2bDirectConnectOutbound", {})

        if _check_outbound_section(b2b_collab):
            findings.append(Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.FAIL,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id="b2bCollaborationOutbound",
                title="Unrestricted outbound B2B collaboration",
                description=(
                    "Default outbound B2B collaboration policy "
                    "allows all users to access all applications in "
                    "any external tenant."
                ),
                remediation=self.metadata.remediation.recommendation,
            ))

        if _check_outbound_section(b2b_direct):
            findings.append(Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.FAIL,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id="b2bDirectConnectOutbound",
                title="Unrestricted outbound B2B direct connect",
                description=(
                    "Default outbound B2B direct connect policy "
                    "allows all users to access all applications in "
                    "any external tenant."
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
                resource_id="outbound",
                title="Outbound cross-tenant access is restricted",
                description=(
                    "Default outbound cross-tenant access policies "
                    "are not fully open."
                ),
                remediation="",
            ))

        return findings
