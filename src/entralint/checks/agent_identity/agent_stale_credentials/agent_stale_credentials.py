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
    from entralint.core.models import AgentIdentity

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


def _parse_dt(value: str | None) -> datetime | None:
    """Parse an ISO-8601 timestamp, tolerating a trailing 'Z'."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _last_sign_in(agent: AgentIdentity) -> datetime | None:
    """Return the most recent sign-in timestamp for an agent, if available.

    Uses ``signInActivity`` when the Graph surface exposes it for agent
    service principals, considering both interactive and non-interactive
    sign-ins. Returns ``None`` when no telemetry is present.
    """
    activity = agent.sign_in_activity
    if not activity:
        return None
    candidates = [
        _parse_dt(activity.get("lastSignInDateTime")),
        _parse_dt(activity.get("lastNonInteractiveSignInDateTime")),
    ]
    valid = [c for c in candidates if c is not None]
    return max(valid) if valid else None


class AgentStaleCredentials(BaseCheck):
    """Flags stale enabled agents by last sign-in, falling back to age."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        findings: list[Finding] = []
        now = datetime.now(tz=UTC)
        cutoff = now - timedelta(days=STALE_DAYS)

        for agent in context.agent_identities:
            if not agent.account_enabled:
                continue

            # Prefer real sign-in telemetry when present; otherwise fall
            # back to creation date as an age-based proxy.
            last_active = _last_sign_in(agent)
            if last_active is not None:
                if last_active >= cutoff:
                    continue
                idle_days = (now - last_active).days
                findings.append(Finding(
                    check_id=self.metadata.check_id,
                    check_version=self.metadata.check_version,
                    status=Status.FAIL,
                    severity=self.metadata.severity,
                    resource_type=self.metadata.resource_type,
                    resource_id=agent.id,
                    title=(
                        f"Agent '{agent.display_name}' has no sign-in for "
                        f"{idle_days} days and is still enabled"
                    ),
                    description=(
                        f"Agent identity last signed in {idle_days} days ago "
                        f"(threshold: {STALE_DAYS}) and is still enabled. "
                        f"Disable or remove it if it is no longer in use."
                    ),
                    remediation=self.metadata.remediation.recommendation,
                ))
                continue

            created = _parse_dt(agent.created_date_time)
            if created is None:
                continue

            if created < cutoff:
                age_days = (now - created).days
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
                        f"is still enabled. No sign-in telemetry was "
                        f"available; review sign-in logs to confirm "
                        f"active usage."
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
