"""Check: Ensure guest user access is restricted."""

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
    Path(__file__).parent / "user_guest_access_level.metadata.json"
)

# Known guestUserRoleId values.
# Restricted = can only see own profile
_RESTRICTED = "2af84b1e-32c8-42b7-82bc-daa82404023b"
# Limited = can see all users but limited group/app info
_LIMITED = "10dae51f-b6af-4016-8d66-8c2a99b929b3"
# Same as members = full directory read
_SAME_AS_MEMBERS = "a0b1b346-4d3e-4e8b-98f8-753987be4970"


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


class UserGuestAccessLevel(BaseCheck):
    """Checks that guest user access is restricted."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        policy = context.authorization_policy
        guest_role_id = policy.get("guestUserRoleId", "")

        if guest_role_id == _RESTRICTED:
            return [
                Finding(
                    check_id=self.metadata.check_id,
                    status=Status.PASS,
                    severity=self.metadata.severity,
                    title="Guest access restricted to own profile",
                )
            ]

        if guest_role_id == _SAME_AS_MEMBERS:
            return [
                Finding(
                    check_id=self.metadata.check_id,
                    status=Status.FAIL,
                    severity=self.metadata.severity,
                    resource_type=self.metadata.resource_type,
                    title="Guest users have same access as members",
                    description=(
                        "Guest users can read all directory objects "
                        "including users, groups, and applications."
                    ),
                    remediation=self.metadata.remediation.recommendation,
                )
            ]

        # _LIMITED or unrecognized — flag as medium concern
        return [
            Finding(
                check_id=self.metadata.check_id,
                status=Status.FAIL,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                title="Guest access not fully restricted",
                description=(
                    "Guest users have limited directory access. "
                    "Consider restricting to own profile only."
                ),
                remediation=self.metadata.remediation.recommendation,
            )
        ]
