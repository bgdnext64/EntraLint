"""Check: Ensure app registrations have no expired or expiring credentials."""

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
    Path(__file__).parent / "app_credential_expiry.metadata.json"
)

EXPIRY_WARNING_DAYS = 30


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
    )


def _parse_datetime(dt_str: str) -> datetime:
    """Parse an ISO 8601 datetime string from Graph API."""
    # Graph returns e.g. "2025-06-01T00:00:00Z"
    cleaned = dt_str.replace("Z", "+00:00")
    return datetime.fromisoformat(cleaned)


class AppCredentialExpiry(BaseCheck):
    """Checks app registrations for expired or soon-expiring credentials."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        now = datetime.now(UTC)
        warning_threshold = now + timedelta(days=EXPIRY_WARNING_DAYS)
        findings: list[Finding] = []

        for app in context.applications:
            all_creds = [
                ("secret", c) for c in app.password_credentials
            ] + [
                ("certificate", c) for c in app.key_credentials
            ]

            for cred_type, cred in all_creds:
                if not cred.end_date_time:
                    continue

                expiry = _parse_datetime(cred.end_date_time)
                cred_label = cred.display_name or cred.key_id[:8]

                if expiry < now:
                    findings.append(Finding(
                        check_id=self.metadata.check_id,
                        check_version=self.metadata.check_version,
                        status=Status.FAIL,
                        severity=Severity.HIGH,
                        resource_type=self.metadata.resource_type,
                        resource_id=app.app_id,
                        title=f"Expired {cred_type}: {app.display_name}",
                        description=(
                            f"App '{app.display_name}' has an expired "
                            f"{cred_type} '{cred_label}' "
                            f"(expired {expiry.date().isoformat()})."
                        ),
                        remediation=self.metadata.remediation.recommendation,
                    ))
                elif expiry < warning_threshold:
                    days_left = (expiry - now).days
                    findings.append(Finding(
                        check_id=self.metadata.check_id,
                        check_version=self.metadata.check_version,
                        status=Status.FAIL,
                        severity=Severity.MEDIUM,
                        resource_type=self.metadata.resource_type,
                        resource_id=app.app_id,
                        title=f"Expiring {cred_type}: {app.display_name}",
                        description=(
                            f"App '{app.display_name}' has a {cred_type} "
                            f"'{cred_label}' expiring in {days_left} day(s) "
                            f"({expiry.date().isoformat()})."
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
                title="No expired or expiring app credentials found",
                description=(
                    "All app registration credentials are valid and not "
                    f"expiring within the next {EXPIRY_WARNING_DAYS} days."
                ),
            ))

        return findings
