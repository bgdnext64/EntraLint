"""Check: Detect stale guest accounts with no recent sign-in."""

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

_METADATA_PATH = Path(__file__).parent / "user_stale_guests.metadata.json"

STALE_DAYS = 90


def _load_metadata() -> CheckMetadata:
    raw = json.loads(_METADATA_PATH.read_text(encoding="utf-8"))
    r = raw["Remediation"]
    return CheckMetadata(
        check_id=raw["CheckID"],
        check_version=raw["CheckVersion"],
        check_title=raw["CheckTitle"],
        service_name=raw["ServiceName"],
        severity=Severity(raw["Severity"]),
        resource_type=raw["ResourceType"],
        description=raw["Description"],
        risk=raw["Risk"],
        remediation=Remediation(recommendation=r["Recommendation"], url=r.get("Url", "")),
        frameworks=raw["Frameworks"],
        graph_api_endpoints=raw["GraphAPIEndpoints"],
        required_permissions=raw["RequiredPermissions"],
        required_license=raw.get("RequiredLicense"),
        depends_on=raw.get("DependsOn", []),
        source_notes=raw.get("SourceNotes", ""),
    )


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        cleaned = value.replace("Z", "+00:00")
        return datetime.fromisoformat(cleaned)
    except (ValueError, TypeError):
        return None


class UserStaleGuests(BaseCheck):
    """Flags guest accounts with no sign-in in the last 90 days."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        guests = [u for u in context.users if u.user_type == "Guest"]

        if not guests:
            return [Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.PASS,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id="tenant-wide",
                title="No guest accounts found",
                description="No guest accounts exist in the tenant.",
            )]

        cutoff = datetime.now(UTC) - timedelta(days=STALE_DAYS)
        stale: list[str] = []

        for guest in guests:
            activity = guest.sign_in_activity or {}
            last_sign_in = _parse_dt(
                activity.get("lastSignInDateTime")
                or activity.get("lastNonInteractiveSignInDateTime")
            )
            if last_sign_in is None:
                # No sign-in data at all — check creation date
                created = _parse_dt(guest.created_date_time)
                if created and created < cutoff:
                    stale.append(guest.display_name or guest.user_principal_name)
            elif last_sign_in < cutoff:
                stale.append(guest.display_name or guest.user_principal_name)

        if stale:
            return [Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.FAIL,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id="tenant-wide",
                title=f"{len(stale)} stale guest accounts ({STALE_DAYS}+ days inactive)",
                description=(
                    f"Found {len(stale)} guest accounts with no sign-in in the "
                    f"last {STALE_DAYS} days: "
                    f"{', '.join(stale[:10])}{'...' if len(stale) > 10 else ''}."
                ),
                remediation=self.metadata.remediation.recommendation,
            )]

        return [Finding(
            check_id=self.metadata.check_id,
            check_version=self.metadata.check_version,
            status=Status.PASS,
            severity=self.metadata.severity,
            resource_type=self.metadata.resource_type,
            resource_id="tenant-wide",
            title="All guest accounts have recent sign-in activity",
            description=(
                f"All {len(guests)} guest accounts have"
                f" signed in within the last {STALE_DAYS}"
                " days."
            ),
        )]
