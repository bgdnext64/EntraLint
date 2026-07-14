"""Check: Ensure agent identities reference an existing blueprint."""

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
    Path(__file__).parent / "agent_orphaned_blueprint.metadata.json"
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


class AgentOrphanedBlueprint(BaseCheck):
    """Flags agent identities whose referenced blueprint no longer exists."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        # Without any blueprint data we cannot distinguish an orphan from a
        # skipped/unauthorized blueprint enumeration; skip to avoid false
        # positives.
        if not context.agent_identity_blueprints:
            return self.skip(
                "No agent blueprint data available to resolve references",
                status=Status.SKIPPED_DEPENDENCY,
            )

        known_ids = {
            bp.id for bp in context.agent_identity_blueprints if bp.id
        }
        known_app_ids = {
            bp.app_id
            for bp in context.agent_identity_blueprints
            if bp.app_id
        }

        findings: list[Finding] = []
        for agent in context.agent_identities:
            bp_ref = agent.agent_identity_blueprint_id
            if not bp_ref:
                continue
            if bp_ref in known_ids or bp_ref in known_app_ids:
                continue
            findings.append(Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.FAIL,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id=agent.id,
                title=(
                    f"Agent '{agent.display_name}' references a missing "
                    f"blueprint"
                ),
                description=(
                    f"Agent identity references blueprint '{bp_ref}', which "
                    f"was not found in the tenant. The agent is orphaned and "
                    f"no longer inherits blueprint-level restrictions."
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
                title="All agent identities reference an existing blueprint",
            ))

        return findings
