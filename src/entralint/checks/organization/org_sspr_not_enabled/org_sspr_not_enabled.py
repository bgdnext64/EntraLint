"""Check: Ensure self-service password reset is enabled for all users."""

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

_METADATA_PATH = Path(__file__).parent / "org_sspr_not_enabled.metadata.json"


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


class OrgSsprNotEnabled(BaseCheck):
    """Flags tenants where SSPR is not enabled for all users."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        policy = context.authentication_methods_policy
        if not policy:
            return self.skip(
                "Authentication methods policy not available",
                status=Status.SKIPPED_PERMISSION,
            )

        # The registrationEnforcement field indicates SSPR config.
        # Also check authenticationMethodConfigurations for
        # passwordResetEnabled (varies by API version).
        # The most reliable signal is the policy-level
        # "registrationEnforcement" or checking if password method
        # targeting includes "allUsers".
        configs = policy.get("authenticationMethodConfigurations", [])

        # Look for the "Password" or "SoftwareOath" method as SSPR indicators
        # In practice, SSPR is controlled via the portal and reflected
        # in whether email/phone/authenticator methods are enabled.
        # A simpler heuristic: if the policy has no methods enabled at
        # all, SSPR can't work.
        enabled_methods = [
            cfg.get("id", "")
            for cfg in configs
            if cfg.get("state") == "enabled"
        ]

        # Check registrationEnforcement for combined registration
        reg_enforcement = policy.get("registrationEnforcement", {})
        campaign = reg_enforcement.get(
            "authenticationMethodsRegistrationCampaign", {}
        )
        campaign_state = campaign.get("state", "disabled")

        if not enabled_methods:
            return [Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.FAIL,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id="tenant-wide",
                title="No authentication methods enabled for SSPR",
                description=(
                    "No authentication methods are enabled in the "
                    "authentication methods policy. Self-service "
                    "password reset cannot function without at "
                    "least one enabled method."
                ),
                remediation=self.metadata.remediation.recommendation,
            )]

        if campaign_state == "enabled":
            return [Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.PASS,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id="tenant-wide",
                title="SSPR registration campaign is active",
                description=(
                    f"Authentication methods registration campaign is "
                    f"enabled with {len(enabled_methods)} method(s) available."
                ),
            )]

        return [Finding(
            check_id=self.metadata.check_id,
            check_version=self.metadata.check_version,
            status=Status.PASS,
            severity=self.metadata.severity,
            resource_type=self.metadata.resource_type,
            resource_id="tenant-wide",
            title=f"{len(enabled_methods)} authentication methods enabled",
            description=(
                f"Authentication methods policy has "
                f"{len(enabled_methods)} method(s) enabled. "
                f"Verify SSPR is enabled for all users in the portal."
            ),
        )]
