"""Check: Ensure MFA is required for Azure Management access."""

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

_METADATA_PATH = Path(__file__).parent / "ca_mfa_azure_management.metadata.json"

# Well-known app ID for Microsoft Azure Management (portal + ARM APIs)
AZURE_MANAGEMENT_APP_ID = "797f4846-ba00-4fd7-ba43-dac1f8f63013"


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
    )


class CaMfaAzureManagement(BaseCheck):
    """Checks for a CA policy requiring MFA for Azure Management access."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        for policy in context.conditional_access_policies:
            if policy.state != "enabled":
                continue

            # Check if Azure Management is in the target apps
            apps = policy.conditions.applications.include_applications
            targets_azure = (
                AZURE_MANAGEMENT_APP_ID in apps or "All" in apps
            )
            if not targets_azure:
                continue

            if policy.grant_controls is None:
                continue

            has_mfa = "mfa" in policy.grant_controls.built_in_controls
            has_auth_strength = (
                policy.grant_controls.authentication_strength is not None
            )

            if has_mfa or has_auth_strength:
                return [
                    Finding(
                        check_id=self.metadata.check_id,
                        check_version=self.metadata.check_version,
                        status=Status.PASS,
                        severity=self.metadata.severity,
                        resource_type=self.metadata.resource_type,
                        resource_id=policy.id,
                        title="MFA required for Azure Management",
                        description=(
                            f"Policy '{policy.display_name}' enforces MFA "
                            f"for Azure Management access."
                        ),
                    )
                ]

        return [
            Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.FAIL,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id="tenant-wide",
                title="No CA policy requires MFA for Azure Management",
                description=(
                    "No enabled Conditional Access policy enforces MFA for "
                    "the Azure Management portal and ARM APIs. This means "
                    "compromised credentials can manage all Azure resources."
                ),
                remediation=self.metadata.remediation.recommendation,
                frameworks=self.metadata.frameworks,
            )
        ]
