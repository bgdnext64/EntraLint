"""Check: Review admin-consented delegated permissions with broad scope."""

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
    Path(__file__).parent / "sp_excessive_delegated.metadata.json"
)

# Delegated scopes considered high-risk when admin-consented for all users.
HIGH_RISK_SCOPES = {
    "mail.readwrite",
    "mail.send",
    "mail.read",
    "files.readwrite.all",
    "sites.readwrite.all",
    "directory.readwrite.all",
    "group.readwrite.all",
    "user.readwrite.all",
    "rolemangement.readwrite.directory",
    "calendars.readwrite",
    "contacts.readwrite",
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


class SpExcessiveDelegated(BaseCheck):
    """Flags admin-consented delegated grants with high-risk scopes."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def _resolve_sp_name(
        self, client_id: str, context: TenantContext
    ) -> str:
        """Look up the display name for a service principal ID."""
        for sp in context.service_principals:
            if sp.id == client_id:
                return sp.display_name
        return client_id

    def execute(self, context: TenantContext) -> list[Finding]:
        findings: list[Finding] = []

        for grant in context.oauth2_permission_grants:
            consent_type = grant.get("consentType", "")
            if consent_type != "AllPrincipals":
                continue

            scope_str = grant.get("scope", "")
            scopes = {s.strip().lower() for s in scope_str.split()}
            dangerous = scopes & HIGH_RISK_SCOPES

            if not dangerous:
                continue

            client_id = grant.get("clientId", "")
            sp_name = self._resolve_sp_name(client_id, context)

            findings.append(Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.FAIL,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id=client_id,
                title=(
                    f"Excessive delegated permissions: {sp_name}"
                ),
                description=(
                    f"App '{sp_name}' has admin consent for all "
                    f"users with high-risk scopes: "
                    f"{', '.join(sorted(dangerous))}"
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
                    "No excessive admin-consented delegated "
                    "permissions found"
                ),
                description=(
                    "No OAuth2 permission grants with admin consent "
                    "and high-risk scopes were detected."
                ),
            ))

        return findings
