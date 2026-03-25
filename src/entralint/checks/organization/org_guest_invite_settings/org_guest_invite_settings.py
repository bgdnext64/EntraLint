"""Check: Ensure guest invitation settings are not overly permissive."""

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
    Path(__file__).parent / "org_guest_invite_settings.metadata.json"
)

# Permissive settings — everyone or all members can invite guests.
PERMISSIVE_INVITE_VALUES = {"everyone", "adminsGuestInvitersAndAllMembers"}


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


class OrgGuestInviteSettings(BaseCheck):
    """Flags tenants where guest invitations are overly permissive."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        policy = context.authorization_policy
        if not policy:
            return [Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.FAIL,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id="authorizationPolicy",
                title="Authorization policy not available",
                description=(
                    "Could not read the authorization policy. "
                    "Ensure Policy.Read.All permission is granted."
                ),
                remediation=self.metadata.remediation.recommendation,
            )]

        allow_invites = policy.get("allowInvitesFrom", "everyone")

        if allow_invites in PERMISSIVE_INVITE_VALUES:
            return [Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.FAIL,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id="authorizationPolicy",
                title=(
                    f"Guest invite setting too permissive: "
                    f"{allow_invites}"
                ),
                description=(
                    f"allowInvitesFrom is set to '{allow_invites}'. "
                    f"This allows too many users to invite external "
                    f"guests. Restrict to admins and guest inviters."
                ),
                remediation=self.metadata.remediation.recommendation,
            )]

        return [Finding(
            check_id=self.metadata.check_id,
            check_version=self.metadata.check_version,
            status=Status.PASS,
            severity=self.metadata.severity,
            resource_type=self.metadata.resource_type,
            resource_id="authorizationPolicy",
            title=(
                f"Guest invite setting is restricted: {allow_invites}"
            ),
            description=(
                f"allowInvitesFrom is set to '{allow_invites}', "
                f"which restricts guest invitations appropriately."
            ),
        )]
