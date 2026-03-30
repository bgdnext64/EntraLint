"""Check: Detect applications with already-expired credentials."""

from __future__ import annotations

import json
from datetime import UTC, datetime
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

_METADATA_PATH = Path(__file__).parent / "app_already_expired_creds.metadata.json"


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


def _is_expired(end_dt: str | None) -> bool:
    if not end_dt:
        return False
    try:
        dt = datetime.fromisoformat(end_dt.replace("Z", "+00:00"))
        return dt < datetime.now(UTC)
    except (ValueError, TypeError):
        return False


class AppAlreadyExpiredCreds(BaseCheck):
    """Flags applications with credentials that have already expired."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        if not context.applications:
            return self.skip(
                "No applications available",
                status=Status.SKIPPED_PERMISSION,
            )

        findings: list[Finding] = []
        for app in context.applications:
            expired_count = 0
            for cred in app.password_credentials:
                if _is_expired(cred.end_date_time):
                    expired_count += 1
            for cred in app.key_credentials:
                if _is_expired(cred.end_date_time):
                    expired_count += 1

            if expired_count > 0:
                findings.append(Finding(
                    check_id=self.metadata.check_id,
                    check_version=self.metadata.check_version,
                    status=Status.FAIL,
                    severity=self.metadata.severity,
                    resource_type=self.metadata.resource_type,
                    resource_id=app.id,
                    title=f"{app.display_name}: {expired_count} expired credential(s)",
                    description=(
                        f"Application '{app.display_name}' has {expired_count} "
                        f"expired credential(s) that should be removed."
                    ),
                    remediation=self.metadata.remediation.recommendation,
                ))

        if not findings:
            return [Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.PASS,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id="tenant-wide",
                title="No applications have expired credentials",
                description="All application credentials are still valid or have been cleaned up.",
            )]

        return findings
