"""Check: Ensure all agent identities and blueprints have accountability."""

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
    Path(__file__).parent / "agent_no_accountability.metadata.json"
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


class AgentNoAccountability(BaseCheck):
    """Flags agents/blueprints with no owners and no sponsors."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        findings: list[Finding] = []

        for agent in context.agent_identities:
            if not agent.owners and not agent.sponsors:
                findings.append(Finding(
                    check_id=self.metadata.check_id,
                    check_version=self.metadata.check_version,
                    status=Status.FAIL,
                    severity=self.metadata.severity,
                    resource_type="AgentIdentity",
                    resource_id=agent.id,
                    title=(
                        f"Agent '{agent.display_name}' has no "
                        f"owner or sponsor"
                    ),
                    description=(
                        "Agent identity has zero owners and zero "
                        "sponsors. No one is accountable for this "
                        "agent's permissions and lifecycle."
                    ),
                    remediation=self.metadata.remediation.recommendation,
                ))

        for bp in context.agent_identity_blueprints:
            if not bp.owners and not bp.sponsors:
                findings.append(Finding(
                    check_id=self.metadata.check_id,
                    check_version=self.metadata.check_version,
                    status=Status.FAIL,
                    severity=self.metadata.severity,
                    resource_type="AgentIdentityBlueprint",
                    resource_id=bp.id,
                    title=(
                        f"Blueprint '{bp.display_name}' has no "
                        f"owner or sponsor"
                    ),
                    description=(
                        "Agent identity blueprint has zero owners "
                        "and zero sponsors. All agent instances "
                        "from this blueprint lack accountability."
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
                    "All agents and blueprints have owners "
                    "or sponsors"
                ),
            ))

        return findings
