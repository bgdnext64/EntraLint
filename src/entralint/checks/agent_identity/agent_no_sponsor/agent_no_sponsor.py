"""Check: Ensure agent identities and blueprints have a designated sponsor."""

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

_METADATA_PATH = Path(__file__).parent / "agent_no_sponsor.metadata.json"


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


class AgentNoSponsor(BaseCheck):
    """Flags agent identities and blueprints that have no sponsor."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        findings: list[Finding] = []

        for agent in context.agent_identities:
            if not agent.sponsors:
                findings.append(Finding(
                    check_id=self.metadata.check_id,
                    check_version=self.metadata.check_version,
                    status=Status.FAIL,
                    severity=self.metadata.severity,
                    resource_type="AgentIdentity",
                    resource_id=agent.id,
                    title=(
                        f"Agent '{agent.display_name}' has no sponsor"
                    ),
                    description=(
                        "Agent identity has no designated sponsor. No named "
                        "party is accountable for its recertification and "
                        "decommissioning."
                    ),
                    remediation=self.metadata.remediation.recommendation,
                    frameworks=self.metadata.frameworks,
                ))

        for bp in context.agent_identity_blueprints:
            if not bp.sponsors:
                findings.append(Finding(
                    check_id=self.metadata.check_id,
                    check_version=self.metadata.check_version,
                    status=Status.FAIL,
                    severity=self.metadata.severity,
                    resource_type="AgentIdentityBlueprint",
                    resource_id=bp.id,
                    title=(
                        f"Blueprint '{bp.display_name}' has no sponsor"
                    ),
                    description=(
                        "Agent blueprint has no designated sponsor. Agents "
                        "derived from it lack a named accountable party."
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
                title="All agent identities and blueprints have a sponsor",
            ))

        return findings
