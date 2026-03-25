"""Check: Ensure MFA is required for all users via Conditional Access."""

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

_METADATA_PATH = Path(__file__).parent / "ca_mfa_required_all_users.metadata.json"


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


class CaMfaRequiredAllUsers(BaseCheck):
    """Checks that at least one enabled CA policy enforces MFA for all users."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        policies = context.conditional_access_policies

        # Look for any enabled policy that requires MFA for all users + all apps
        for policy in policies:
            if policy.state != "enabled":
                continue

            # Check if policy targets all users
            users_include = policy.conditions.users.include_users
            if "All" not in users_include:
                continue

            # Check if policy targets all cloud apps
            apps_include = policy.conditions.applications.include_applications
            if "All" not in apps_include:
                continue

            # Check if MFA is in the grant controls
            if policy.grant_controls is None:
                continue

            controls = policy.grant_controls.built_in_controls
            has_mfa = "mfa" in controls

            # Also check for authentication strength (phishing-resistant MFA)
            has_auth_strength = policy.grant_controls.authentication_strength is not None

            if has_mfa or has_auth_strength:
                return [
                    Finding(
                        check_id=self.metadata.check_id,
                        check_version=self.metadata.check_version,
                        status=Status.PASS,
                        severity=self.metadata.severity,
                        resource_type=self.metadata.resource_type,
                        resource_id=policy.id,
                        title="MFA enforced for all users via Conditional Access",
                        description=(
                            f"Policy '{policy.display_name}' enforces MFA "
                            f"for all users across all cloud apps."
                        ),
                    )
                ]

        # No qualifying policy found
        return [
            Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.FAIL,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id="tenant-wide",
                title="No CA policy requires MFA for all users",
                description=(
                    "No enabled Conditional Access policy enforces MFA "
                    "for all users across all cloud apps. "
                    "This was the exact attack vector in the Midnight Blizzard breach."
                ),
                remediation=self.metadata.remediation.recommendation,
                frameworks=self.metadata.frameworks,
            )
        ]
