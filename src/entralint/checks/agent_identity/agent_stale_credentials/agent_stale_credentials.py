"""Check: Ensure stale agent identities are disabled or removed."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
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
    Path(__file__).parent / "agent_stale_credentials.metadata.json"
)

STALE_DAYS = 90


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


class AgentStaleCredentials(BaseCheck):
    """Flags enabled agents older than STALE_DAYS."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        findings: list[Finding] = []
        cutoff = datetime.now(tz=UTC) - timedelta(days=STALE_DAYS)

        for agent in context.agent_identities:
            if not agent.account_enabled:
                continue
            if not agent.created_date_time:
                continue
            try:
                created = datetime.fromisoformat(
                    agent.created_date_time.replace("Z", "+00:00")
                )
            except (ValueError, AttributeError):
                continue

            if created < cutoff:
                age_days = (
                    datetime.now(tz=UTC) - created
                ).days
                findings.append(Finding(
                    check_id=self.metadata.check_id,
                    check_version=self.metadata.check_version,
                    status=Status.FAIL,
                    severity=self.metadata.severity,
                    resource_type=self.metadata.resource_type,
                    resource_id=agent.id,
                    title=(
                        f"Agent '{agent.display_name}' is "
                        f"{age_days} days old and still enabled"
                    ),
                    description=(
                        f"Agent identity was created {age_days} "
                        f"days ago (threshold: {STALE_DAYS}) and "
                        f"is still enabled. Review sign-in logs to "
                        f"confirm active usage."
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
                title="No stale agent identities detected",
            ))

        return findings
