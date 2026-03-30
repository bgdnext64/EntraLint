"""Check: Ensure sign-in frequency is configured for admin sessions."""

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

_METADATA_PATH = Path(__file__).parent / "ca_no_admin_sign_in_frequency.metadata.json"

# Well-known admin roles that should have sign-in frequency
ADMIN_ROLE_IDS = {
    "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
    "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
    "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Administrator
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",  # Privileged Authentication Admin
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",  # Conditional Access Administrator
}


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


class CaNoAdminSignInFrequency(BaseCheck):
    """Flags tenants with no sign-in frequency policy for admin roles."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        if not context.conditional_access_policies:
            return self.skip(
                "No Conditional Access policies available",
                status=Status.SKIPPED_PERMISSION,
            )

        enabled = [
            p for p in context.conditional_access_policies
            if p.state == "enabled"
        ]

        for policy in enabled:
            # Check if policy targets admin roles
            included_roles = set(policy.conditions.users.include_roles)
            targets_all = "All" in policy.conditions.users.include_users
            targets_admins = bool(included_roles & ADMIN_ROLE_IDS) or targets_all

            if not targets_admins:
                continue

            # Check if sign-in frequency is configured
            sc = policy.session_controls
            if sc and sc.sign_in_frequency:
                freq = sc.sign_in_frequency
                if freq.get("isEnabled", True):
                    return [Finding(
                        check_id=self.metadata.check_id,
                        check_version=self.metadata.check_version,
                        status=Status.PASS,
                        severity=self.metadata.severity,
                        resource_type=self.metadata.resource_type,
                        resource_id=policy.id,
                        title="Sign-in frequency is configured for admin sessions",
                        description=(
                            f"Policy '{policy.display_name}' enforces sign-in "
                            f"frequency for admin roles."
                        ),
                    )]

        return [Finding(
            check_id=self.metadata.check_id,
            check_version=self.metadata.check_version,
            status=Status.FAIL,
            severity=self.metadata.severity,
            resource_type=self.metadata.resource_type,
            resource_id="tenant-wide",
            title="No sign-in frequency policy for admin sessions",
            description=(
                "No enabled CA policy enforces sign-in frequency for "
                "privileged admin roles. Admin refresh tokens may persist "
                "indefinitely, increasing the risk of token theft attacks."
            ),
            remediation=self.metadata.remediation.recommendation,
        )]
