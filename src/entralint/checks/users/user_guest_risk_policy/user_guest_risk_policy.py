"""Check: Ensure guest users are covered by risk-based CA policies."""

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

_METADATA_PATH = Path(__file__).parent / "user_guest_risk_policy.metadata.json"


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


def _targets_guests(policy: object) -> bool:
    """Return True if the CA policy includes guest users."""
    from entralint.core.models import ConditionalAccessPolicy

    if not isinstance(policy, ConditionalAccessPolicy):
        return False
    include = policy.conditions.users.include_users
    return any(
        u.lower() in ("all", "guestsorexternalusers")
        for u in include
    )


def _is_risk_policy(policy: object) -> bool:
    """Return True if the policy has sign-in risk or user risk conditions."""
    from entralint.core.models import ConditionalAccessPolicy

    if not isinstance(policy, ConditionalAccessPolicy):
        return False
    return bool(
        policy.conditions.sign_in_risk_levels
        or policy.conditions.user_risk_levels
    )


class UserGuestRiskPolicy(BaseCheck):
    """Flags tenants where guests are not covered by risk-based CA policies."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        if not context.conditional_access_policies:
            return self.skip(
                "No Conditional Access policies available",
                status=Status.SKIPPED_PERMISSION,
            )

        enabled_policies = [
            p for p in context.conditional_access_policies
            if p.state == "enabled"
        ]

        risk_policies = [p for p in enabled_policies if _is_risk_policy(p)]

        if not risk_policies:
            return [Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.FAIL,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id="tenant-wide",
                title="No risk-based Conditional Access policies exist",
                description=(
                    "No enabled CA policies with sign-in risk"
                    " or user risk conditions were found."
                    " Guest users are not protected by"
                    " risk-based policies."
                ),
                remediation=self.metadata.remediation.recommendation,
            )]

        guest_covered = any(_targets_guests(p) for p in risk_policies)

        if guest_covered:
            return [Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.PASS,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id="tenant-wide",
                title="Guest users are covered by risk-based CA policies",
                description=(
                    "At least one risk-based CA policy targets"
                    " all users or explicitly includes guests."
                ),
            )]

        return [Finding(
            check_id=self.metadata.check_id,
            check_version=self.metadata.check_version,
            status=Status.FAIL,
            severity=self.metadata.severity,
            resource_type=self.metadata.resource_type,
            resource_id="tenant-wide",
            title="Guest users not covered by risk-based CA policies",
            description=(
                f"Found {len(risk_policies)} risk-based CA policies, but none "
                f"target 'All users' or 'GuestsOrExternalUsers'. Guest accounts "
                f"are not protected by risk-based sign-in evaluation."
            ),
            remediation=self.metadata.remediation.recommendation,
        )]
