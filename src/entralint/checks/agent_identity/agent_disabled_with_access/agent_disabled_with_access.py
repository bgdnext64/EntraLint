"""Check: Ensure disabled agent identities do not retain permissions."""

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
    Path(__file__).parent / "agent_disabled_with_access.metadata.json"
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


class AgentDisabledWithAccess(BaseCheck):
    """Flags disabled agents that still hold app roles or delegated grants."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        findings: list[Finding] = []

        for agent in context.agent_identities:
            if agent.account_enabled:
                continue

            role_count = len(agent.app_role_assignments)
            grant_count = len(agent.oauth2_permission_grants)
            if role_count == 0 and grant_count == 0:
                continue

            parts: list[str] = []
            if role_count:
                parts.append(f"{role_count} app role assignment(s)")
            if grant_count:
                parts.append(f"{grant_count} delegated grant(s)")

            findings.append(Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.FAIL,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id=agent.id,
                title=(
                    f"Disabled agent '{agent.display_name}' still holds "
                    f"permissions"
                ),
                description=(
                    f"Agent identity is disabled (accountEnabled=false) but "
                    f"retains {' and '.join(parts)}. If re-enabled it would "
                    f"immediately regain this access."
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
                title="No disabled agent identities retain permissions",
            ))

        return findings
