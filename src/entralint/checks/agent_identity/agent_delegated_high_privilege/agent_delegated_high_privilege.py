"""Check: Ensure agent identities do not hold high-risk delegated permissions."""

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
    Path(__file__).parent / "agent_delegated_high_privilege.metadata.json"
)

# Delegated OAuth2 scopes considered high-risk when held by an agent.
# Compared case-insensitively against the space-delimited grant scope string.
HIGH_RISK_DELEGATED_SCOPES: set[str] = {
    "mail.readwrite",
    "mail.send",
    "mail.read",
    "files.readwrite.all",
    "files.read.all",
    "sites.readwrite.all",
    "sites.fullcontrol.all",
    "directory.readwrite.all",
    "directory.accessasuser.all",
    "group.readwrite.all",
    "user.readwrite.all",
    "rolemanagement.readwrite.directory",
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


class AgentDelegatedHighPrivilege(BaseCheck):
    """Flags agent identities holding high-risk delegated permission scopes."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        findings: list[Finding] = []

        for agent in context.agent_identities:
            dangerous: set[str] = set()
            for grant in agent.oauth2_permission_grants:
                scope_str = grant.get("scope", "") or ""
                scopes = {s.strip().lower() for s in scope_str.split()}
                dangerous |= scopes & HIGH_RISK_DELEGATED_SCOPES

            if dangerous:
                findings.append(Finding(
                    check_id=self.metadata.check_id,
                    check_version=self.metadata.check_version,
                    status=Status.FAIL,
                    severity=self.metadata.severity,
                    resource_type=self.metadata.resource_type,
                    resource_id=agent.id,
                    title=(
                        f"Agent '{agent.display_name}' holds high-risk "
                        f"delegated permissions"
                    ),
                    description=(
                        f"Agent identity holds high-risk delegated scopes "
                        f"that let it act on behalf of a user: "
                        f"{', '.join(sorted(dangerous))}."
                    ),
                    remediation=self.metadata.remediation.recommendation,
                    frameworks=self.metadata.frameworks,
                ))

        if not findings:
            findings.append(Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.PASS,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id="tenant-wide",
                title="No agent identities with high-risk delegated permissions",
            ))

        return findings
