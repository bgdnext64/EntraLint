"""Check: Ensure agent identities and blueprints have descriptions."""

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
    Path(__file__).parent / "agent_no_description.metadata.json"
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


class AgentNoDescription(BaseCheck):
    """Flags agents/blueprints missing description or info."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    @staticmethod
    def _has_meaningful_info(info: dict | None) -> bool:
        """Check if the info dict has any non-null values."""
        if not info:
            return False
        return any(v for v in info.values() if v is not None)

    def execute(self, context: TenantContext) -> list[Finding]:
        findings: list[Finding] = []

        for bp in context.agent_identity_blueprints:
            if not bp.description and not self._has_meaningful_info(bp.info):
                findings.append(Finding(
                    check_id=self.metadata.check_id,
                    check_version=self.metadata.check_version,
                    status=Status.FAIL,
                    severity=self.metadata.severity,
                    resource_type="AgentIdentityBlueprint",
                    resource_id=bp.id,
                    title=(
                        f"Blueprint '{bp.display_name}' has no "
                        f"description"
                    ),
                    description=(
                        "Blueprint is missing both description "
                        "and info (URLs). This creates a "
                        "governance gap during review."
                    ),
                    remediation=self.metadata.remediation.recommendation,
                ))

        for agent in context.agent_identities:
            # Agent identities inherit description from blueprint,
            # but check display_name at minimum is meaningful
            if not agent.display_name or agent.display_name == agent.id:
                findings.append(Finding(
                    check_id=self.metadata.check_id,
                    check_version=self.metadata.check_version,
                    status=Status.FAIL,
                    severity=self.metadata.severity,
                    resource_type="AgentIdentity",
                    resource_id=agent.id,
                    title=(
                        f"Agent '{agent.id}' has no meaningful "
                        f"display name"
                    ),
                    description=(
                        "Agent identity has no display name or "
                        "uses its object ID as display name. "
                        "This makes governance review difficult."
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
                    "All agents and blueprints have descriptions"
                ),
            ))

        return findings
