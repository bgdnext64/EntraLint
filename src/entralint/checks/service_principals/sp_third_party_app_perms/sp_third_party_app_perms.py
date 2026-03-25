"""Check: Review third-party SPs with application permissions."""

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
    Path(__file__).parent
    / "sp_third_party_app_perms.metadata.json"
)

# Well-known Microsoft first-party app IDs to exclude.
# These are standard Microsoft service principals present in every tenant.
MICROSOFT_FIRST_PARTY_APP_IDS: set[str] = {
    "00000003-0000-0000-c000-000000000000",  # Microsoft Graph
    "00000001-0000-0000-c000-000000000000",  # Azure AD Graph (legacy)
    "00000002-0000-0ff1-ce00-000000000000",  # Office 365 Exchange Online
    "00000003-0000-0ff1-ce00-000000000000",  # Office 365 SharePoint Online
    "00000004-0000-0ff1-ce00-000000000000",  # Office 365 Skype
    "00000007-0000-0ff1-ce00-000000000000",  # Dynamics 365
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


def _is_third_party(sp: object, app_id_attr: str = "app_id") -> bool:
    """Return True if SP is not a managed identity and not first-party."""
    sp_type = getattr(sp, "service_principal_type", "")
    if sp_type == "ManagedIdentity":
        return False
    app_id = getattr(sp, app_id_attr, "")
    return app_id not in MICROSOFT_FIRST_PARTY_APP_IDS


class SpThirdPartyAppPerms(BaseCheck):
    """Flags third-party SPs that have application-level permissions."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        findings: list[Finding] = []

        # Build SP lookup by id
        sp_by_id: dict[str, object] = {
            sp.id: sp for sp in context.service_principals
        }

        # Group appRoleAssignments by principal (the SP that holds the perm)
        by_principal: dict[str, list[str]] = {}
        for ara in context.app_role_assignments:
            sp = sp_by_id.get(ara.principal_id)
            if sp is None:
                continue
            if not _is_third_party(sp):
                continue
            key = ara.principal_display_name or ara.principal_id
            resource = ara.resource_display_name or ara.resource_id
            by_principal.setdefault(key, []).append(resource)

        for principal_name, resources in sorted(by_principal.items()):
            unique_count = len(set(resources))
            findings.append(Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.FAIL,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id=principal_name,
                title=(
                    f"Third-party SP with app permissions: "
                    f"{principal_name}"
                ),
                description=(
                    f"Third-party app '{principal_name}' has "
                    f"{len(resources)} application permission(s) "
                    f"across {unique_count} resource(s)."
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
                resource_id="tenant-wide",
                title=(
                    "No third-party SPs with application "
                    "permissions found"
                ),
                description=(
                    "No third-party service principals have been "
                    "granted application-level permissions."
                ),
            ))

        return findings
