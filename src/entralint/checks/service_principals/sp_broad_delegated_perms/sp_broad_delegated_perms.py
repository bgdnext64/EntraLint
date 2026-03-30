"""Check: Detect SPs with overly broad delegated permission grants."""

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
    Path(__file__).parent / "sp_broad_delegated_perms.metadata.json"
)

# Scope strings considered overly broad for delegated permissions
_BROAD_SCOPES = {
    "full_access_as_user",
    "user_impersonation",
    "user.readwrite.all",
    "directory.readwrite.all",
    "mail.readwrite",
    "mail.send",
    "files.readwrite.all",
    "sites.readwrite.all",
    "group.readwrite.all",
    "rolemangement.readwrite.directory",
    "application.readwrite.all",
    "calendars.readwrite",
}

# Minimum number of broad scopes to flag (one is enough)
_MIN_BROAD_COUNT = 3


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


class SpBroadDelegatedPerms(BaseCheck):
    """Flags SPs with many broad delegated permission grants."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def _resolve_sp_name(
        self, client_id: str, context: TenantContext
    ) -> str:
        for sp in context.service_principals:
            if sp.id == client_id:
                return sp.display_name
        return client_id

    def execute(self, context: TenantContext) -> list[Finding]:
        # Aggregate scopes per client across all grants
        client_scopes: dict[str, set[str]] = {}
        for grant in context.oauth2_permission_grants:
            client_id = grant.get("clientId", "")
            scope_str = grant.get("scope", "")
            scopes = {s.strip().lower() for s in scope_str.split() if s.strip()}
            if client_id not in client_scopes:
                client_scopes[client_id] = set()
            client_scopes[client_id] |= scopes

        findings: list[Finding] = []
        for client_id, scopes in client_scopes.items():
            broad = scopes & _BROAD_SCOPES
            if len(broad) < _MIN_BROAD_COUNT:
                continue

            sp_name = self._resolve_sp_name(client_id, context)
            findings.append(Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.FAIL,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id=client_id,
                title=f"Broad delegated permissions: {sp_name}",
                description=(
                    f"SP '{sp_name}' has {len(broad)} broad delegated "
                    f"scopes: {', '.join(sorted(broad))}"
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
                title="No SPs with overly broad delegated permissions",
                description=(
                    "No service principals have 3+ broad delegated "
                    "permission scopes."
                ),
                remediation="",
            ))

        return findings
