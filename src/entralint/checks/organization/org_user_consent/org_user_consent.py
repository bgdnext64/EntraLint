"""Check: Ensure user consent to applications is restricted."""

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
    Path(__file__).parent / "org_user_consent.metadata.json"
)

# Values that indicate user consent is NOT restricted.
# See: https://learn.microsoft.com/en-us/graph/api/resources/authorizationpolicy
PERMISSIVE_CONSENT_VALUES = {
    "managePermissionGrantsForSelf.microsoft-user-default-legacy",
    "ManagePermissionGrantsForSelf.microsoft-user-default-legacy",
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


class OrgUserConsent(BaseCheck):
    """Flags tenants where users can consent to apps without admin approval."""

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

        # Check defaultUserRolePermissions.permissionGrantPoliciesAssigned
        default_role = policy.get("defaultUserRolePermissions", {})
        consent_policies = set(
            default_role.get("permissionGrantPoliciesAssigned", [])
        )

        # If any permissive consent policy is assigned, consent is too open
        is_permissive = bool(
            consent_policies & PERMISSIVE_CONSENT_VALUES
        )

        if is_permissive:
            return [Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.FAIL,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id="authorizationPolicy",
                title="User consent to applications is not restricted",
                description=(
                    "Users can consent to third-party applications "
                    "without admin approval. Consent policies: "
                    f"{', '.join(sorted(consent_policies))}"
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
            title="User consent to applications is restricted",
            description=(
                "Users cannot consent to third-party applications "
                "without admin approval."
            ),
        )]
