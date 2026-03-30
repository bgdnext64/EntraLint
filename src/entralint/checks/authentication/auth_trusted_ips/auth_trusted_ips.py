"""Check: Review named locations configured as trusted for MFA bypass."""

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
    Path(__file__).parent / "auth_trusted_ips.metadata.json"
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


class AuthTrustedIps(BaseCheck):
    """Flags named locations marked as trusted that could bypass MFA."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        locations = context.named_locations
        if not locations:
            return [Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.PASS,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id="tenant",
                title="No named locations configured",
                description="No named locations exist to review.",
                remediation="",
            )]

        findings: list[Finding] = []
        for loc in locations:
            is_trusted = loc.get("isTrusted", False)
            if not is_trusted:
                continue

            display_name = loc.get("displayName", loc.get("id", "unknown"))
            findings.append(Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.FAIL,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id=loc.get("id", "unknown"),
                title=f"Trusted named location: {display_name}",
                description=(
                    f"Named location '{display_name}' is marked as "
                    "trusted. CA policies may skip MFA for sign-ins "
                    "from this location. Verify it represents a "
                    "corporate-controlled network."
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
                resource_id="tenant",
                title="No trusted named locations",
                description=(
                    "No named locations are marked as trusted."
                ),
                remediation="",
            )]

        return findings
