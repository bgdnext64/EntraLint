"""Check: Ensure user risk policy blocks high-risk users."""

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

_METADATA_PATH = Path(__file__).parent / "ca_block_risky_users.metadata.json"


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


class CaBlockRiskyUsers(BaseCheck):
    """Checks for a CA policy responding to user risk levels."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        for policy in context.conditional_access_policies:
            if policy.state != "enabled":
                continue

            risk_levels = {
                r.lower() for r in policy.conditions.user_risk_levels
            }
            if "high" not in risk_levels:
                continue

            # Must block or require password change (+ MFA)
            if policy.grant_controls is None:
                continue

            controls = policy.grant_controls.built_in_controls
            if "block" in controls or "passwordChange" in controls or "mfa" in controls:
                return [
                    Finding(
                        check_id=self.metadata.check_id,
                        check_version=self.metadata.check_version,
                        status=Status.PASS,
                        severity=self.metadata.severity,
                        resource_type=self.metadata.resource_type,
                        resource_id=policy.id,
                        title="User risk policy configured",
                        description=(
                            f"Policy '{policy.display_name}' responds to "
                            f"high user risk."
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
                title="No user risk policy configured",
                description=(
                    "No enabled Conditional Access policy responds to high "
                    "user risk. Accounts flagged as compromised by Identity "
                    "Protection will continue to operate normally."
                ),
                remediation=self.metadata.remediation.recommendation,
                frameworks=self.metadata.frameworks,
            )
        ]
