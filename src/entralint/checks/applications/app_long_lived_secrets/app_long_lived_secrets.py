"""Check: Detect applications with long-lived client secrets."""

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
    Path(__file__).parent / "app_long_lived_secrets.metadata.json"
)

_MAX_LIFETIME_DAYS = 365


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


def _parse_dt(val: str | None) -> datetime | None:
    if not val:
        return None
    # Graph API returns ISO 8601 with Z suffix
    val = val.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(val)
    except ValueError:
        return None


class AppLongLivedSecrets(BaseCheck):
    """Flags apps with secrets valid for more than 1 year."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        now = datetime.now(tz=UTC)
        threshold = now + timedelta(days=_MAX_LIFETIME_DAYS)
        findings: list[Finding] = []

        for app in context.applications:
            for cred in app.password_credentials:
                end_dt = _parse_dt(cred.end_date_time)
                if end_dt is None:
                    # No expiry = long-lived
                    findings.append(
                        Finding(
                            check_id=self.metadata.check_id,
                            status=Status.FAIL,
                            severity=self.metadata.severity,
                            resource_type=self.metadata.resource_type,
                            resource_id=app.id,
                            title=(
                                f"Secret with no expiry: "
                                f"{app.display_name}"
                            ),
                            remediation=self.metadata.remediation.recommendation,
                        )
                    )
                elif end_dt > threshold:
                    remaining = (end_dt - now).days
                    findings.append(
                        Finding(
                            check_id=self.metadata.check_id,
                            status=Status.FAIL,
                            severity=self.metadata.severity,
                            resource_type=self.metadata.resource_type,
                            resource_id=app.id,
                            title=(
                                f"Long-lived secret ({remaining}d): "
                                f"{app.display_name}"
                            ),
                            remediation=self.metadata.remediation.recommendation,
                        )
                    )

        if not findings:
            findings.append(
                Finding(
                    check_id=self.metadata.check_id,
                    status=Status.PASS,
                    severity=self.metadata.severity,
                    title="No apps with long-lived secrets",
                )
            )

        return findings
