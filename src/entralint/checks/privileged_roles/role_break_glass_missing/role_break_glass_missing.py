"""Check: Ensure emergency access (break-glass) accounts exist."""

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
    Path(__file__).parent / "role_break_glass_missing.metadata.json"
)

# Global Administrator role template ID (same in all tenants)
GLOBAL_ADMIN_ROLE_TEMPLATE_ID = "62e90394-69f5-4237-9190-012177145e10"

# Common patterns for break-glass account names
BREAK_GLASS_PATTERNS = {
    "breakglass",
    "break-glass",
    "break_glass",
    "emergency",
    "emergencyaccess",
    "emergency-access",
    "emergency_access",
    "eba",
    "eba1",
    "eba2",
}


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


def _is_break_glass_name(name: str) -> bool:
    """Check if a display name or UPN looks like a break-glass account."""
    lower = name.lower().replace(" ", "")
    return any(pattern in lower for pattern in BREAK_GLASS_PATTERNS)


class RoleBreakGlassMissing(BaseCheck):
    """Flags tenants without identifiable break-glass accounts."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        # Find Global Admin principal IDs
        ga_principal_ids: set[str] = set()
        for assignment in context.role_assignments:
            if assignment.role_definition_id == GLOBAL_ADMIN_ROLE_TEMPLATE_ID:
                ga_principal_ids.add(assignment.principal_id)

        if not ga_principal_ids:
            return self.skip(
                "No Global Administrator role assignments found "
                "(role assignment data may be missing)",
                status=Status.SKIPPED_PERMISSION,
            )

        # Build user lookup
        users_by_id = {u.id: u for u in context.users}

        # Check CA policy exclusions — break-glass accounts should
        # be excluded from at least one CA policy
        excluded_user_ids: set[str] = set()
        for policy in context.conditional_access_policies:
            if policy.state != "enabled":
                continue
            users_cond = policy.conditions.users
            excluded_user_ids.update(users_cond.exclude_users)

        # Look for break-glass candidates among Global Admins
        break_glass_found: list[str] = []
        for principal_id in ga_principal_ids:
            user = users_by_id.get(principal_id)
            if user is None:
                continue

            name = user.display_name
            upn = user.user_principal_name

            is_candidate = (
                _is_break_glass_name(name)
                or _is_break_glass_name(upn)
                or principal_id in excluded_user_ids
            )
            if is_candidate:
                break_glass_found.append(name or upn)

        if break_glass_found:
            return [Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.PASS,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id="tenant-wide",
                title=(
                    f"Break-glass account(s) found: "
                    f"{', '.join(break_glass_found)}"
                ),
                description=(
                    f"Found {len(break_glass_found)} potential "
                    f"emergency access account(s) among Global "
                    f"Administrators."
                ),
            )]

        return [Finding(
            check_id=self.metadata.check_id,
            check_version=self.metadata.check_version,
            status=Status.FAIL,
            severity=self.metadata.severity,
            resource_type=self.metadata.resource_type,
            resource_id="tenant-wide",
            title="No break-glass accounts detected",
            description=(
                f"No Global Administrator accounts match common "
                f"break-glass naming patterns and none are excluded "
                f"from Conditional Access policies. Found "
                f"{len(ga_principal_ids)} Global Admin(s) but none "
                f"appear to be emergency access accounts."
            ),
            remediation=self.metadata.remediation.recommendation,
        )]
