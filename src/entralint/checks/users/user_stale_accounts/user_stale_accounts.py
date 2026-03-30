"""Check: Identify stale user accounts with no recent sign-in activity."""

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

_METADATA_PATH = Path(__file__).parent / "user_stale_accounts.metadata.json"

STALE_THRESHOLD_DAYS = 90


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


class UserStaleAccounts(BaseCheck):
    """Flags enabled users with no sign-in activity in 90+ days."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        # Check if signInActivity data is available
        has_sign_in_data = any(
            u.sign_in_activity is not None for u in context.users
        )
        if not has_sign_in_data:
            return self.skip(
                "signInActivity data not available (requires P1+ license)",
                status=Status.SKIPPED_LICENSE,
            )

        findings: list[Finding] = []
        cutoff = datetime.now(UTC) - timedelta(days=STALE_THRESHOLD_DAYS)

        for user in context.users:
            if not user.account_enabled:
                continue
            if user.user_type != "Member":
                continue

            activity = user.sign_in_activity or {}
            last_sign_in = activity.get("lastSignInDateTime")
            last_non_interactive = activity.get(
                "lastNonInteractiveSignInDateTime"
            )

            # Use the most recent of interactive or non-interactive
            last_active: datetime | None = None
            for ts_str in (last_sign_in, last_non_interactive):
                if ts_str:
                    try:
                        ts = datetime.fromisoformat(
                            ts_str.replace("Z", "+00:00")
                        )
                        if last_active is None or ts > last_active:
                            last_active = ts
                    except (ValueError, AttributeError):
                        continue

            if last_active is None or last_active < cutoff:
                days_inactive = (
                    (datetime.now(UTC) - last_active).days
                    if last_active
                    else "never"
                )
                findings.append(Finding(
                    check_id=self.metadata.check_id,
                    check_version=self.metadata.check_version,
                    status=Status.FAIL,
                    severity=self.metadata.severity,
                    resource_type=self.metadata.resource_type,
                    resource_id=user.id,
                    title=f"Stale account: {user.display_name}",
                    description=(
                        f"User '{user.display_name}' "
                        f"({user.user_principal_name}) has not signed "
                        f"in for {days_inactive} days."
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
                title="No stale user accounts detected",
                description=(
                    f"All enabled member accounts have signed in "
                    f"within the last {STALE_THRESHOLD_DAYS} days."
                ),
            ))

        return findings
