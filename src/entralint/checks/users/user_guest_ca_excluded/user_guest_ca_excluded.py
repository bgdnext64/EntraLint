"""Check: Detect guest/external users excluded from CA policies."""

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
    Path(__file__).parent / "user_guest_ca_excluded.metadata.json"
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


class UserGuestCaExcluded(BaseCheck):
    """Flags CA policies that exclude guest/external users."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        policies = context.conditional_access_policies
        if not policies:
            return self.skip(
                "No Conditional Access policies configured",
                status=Status.SKIPPED_PERMISSION,
            )

        findings: list[Finding] = []
        for policy in policies:
            if policy.state != "enabled":
                continue
            if self._excludes_guests(policy):
                findings.append(Finding(
                    check_id=self.metadata.check_id,
                    check_version=self.metadata.check_version,
                    status=Status.FAIL,
                    severity=self.metadata.severity,
                    resource_type=self.metadata.resource_type,
                    resource_id=policy.id,
                    title=(
                        f"Guests excluded from policy: "
                        f"{policy.display_name}"
                    ),
                    description=(
                        f"CA policy '{policy.display_name}' explicitly "
                        "excludes guest or external users from "
                        "enforcement."
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
                resource_id="tenant",
                title="No CA policies exclude guest users",
                description=(
                    "No enabled CA policies explicitly exclude "
                    "guest or external users."
                ),
                remediation="",
            ))

        return findings

    @staticmethod
    def _excludes_guests(policy) -> bool:
        """Check if a CA policy explicitly excludes guests."""
        if not policy.conditions or not policy.conditions.users:
            return False
        users = policy.conditions.users
        for u in users.exclude_users or []:
            if u == "GuestsOrExternalUsers":
                return True
        # Check excludeGuestsOrExternalUsers nested object
        guest_obj = getattr(
            users, "exclude_guests_or_external_users", None
        )
        return bool(guest_obj)
