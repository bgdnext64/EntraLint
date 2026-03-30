"""Check: Ensure at least one CA policy targets guest/external users."""

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
    Path(__file__).parent / "ca_guest_not_targeted.metadata.json"
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


class CaGuestNotTargeted(BaseCheck):
    """Flags tenants where no CA policy targets guest/external users."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        policies = context.conditional_access_policies
        if not policies:
            return [Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.FAIL,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id="tenant",
                title="No Conditional Access policies configured",
                description=(
                    "No CA policies exist, so guest/external users "
                    "are not subject to any access controls."
                ),
                remediation=self.metadata.remediation.recommendation,
            )]

        for policy in policies:
            if policy.state == "enabled" and self._targets_guests(policy):
                return [Finding(
                    check_id=self.metadata.check_id,
                    check_version=self.metadata.check_version,
                    status=Status.PASS,
                    severity=self.metadata.severity,
                    resource_type=self.metadata.resource_type,
                    resource_id="tenant",
                    title="CA policy targets guest/external users",
                    description=(
                        f"Policy '{policy.display_name}' targets "
                        "guest or external users."
                    ),
                    remediation="",
                )]

        return [Finding(
            check_id=self.metadata.check_id,
            check_version=self.metadata.check_version,
            status=Status.FAIL,
            severity=self.metadata.severity,
            resource_type=self.metadata.resource_type,
            resource_id="tenant",
            title="No CA policy targets guest/external users",
            description=(
                "No enabled Conditional Access policy explicitly "
                "targets guest or external users. These identities "
                "may bypass all access controls."
            ),
            remediation=self.metadata.remediation.recommendation,
        )]

    @staticmethod
    def _targets_guests(policy) -> bool:
        """Check if a CA policy targets guest/external users."""
        if not policy.conditions or not policy.conditions.users:
            return False
        users = policy.conditions.users

        # Check includeUsers for 'GuestsOrExternalUsers' or 'All'
        for u in users.include_users or []:
            if u in ("GuestsOrExternalUsers", "All"):
                return True

        # Check includeGuestsOrExternalUsers nested object
        guest_obj = getattr(users, "include_guests_or_external_users", None)
        return bool(guest_obj)
