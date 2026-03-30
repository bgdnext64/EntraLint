"""Check: Detect SPs with credentials but no recent sign-in."""

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

_METADATA_PATH = (
    Path(__file__).parent / "sp_stale_credentials.metadata.json"
)


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


def _has_active_credentials(sp) -> bool:
    """Check if SP has any non-expired credentials."""
    now = datetime.now(tz=UTC)
    for cred in sp.password_credentials:
        if cred.end_date_time:
            end = cred.end_date_time.replace("Z", "+00:00")
            try:
                if datetime.fromisoformat(end) > now:
                    return True
            except ValueError:
                continue
        else:
            return True  # no expiry = active
    for cred in sp.key_credentials:
        if cred.end_date_time:
            end = cred.end_date_time.replace("Z", "+00:00")
            try:
                if datetime.fromisoformat(end) > now:
                    return True
            except ValueError:
                continue
        else:
            return True
    return False


class SpStaleCredentials(BaseCheck):
    """Flags SPs with valid credentials but no app role assignments."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        # Build set of SP IDs that have any app role assignments
        # (indicating they are actively used for something).
        active_sp_ids = {
            a.principal_id
            for a in context.app_role_assignments
        }
        # Also consider SPs with oauth2 grants as active.
        for grant in context.oauth2_permission_grants:
            client_id = grant.get("clientId", "")
            if client_id:
                active_sp_ids.add(client_id)

        findings: list[Finding] = []
        for sp in context.service_principals:
            # Skip Microsoft first-party SPs
            if sp.service_principal_type == "ManagedIdentity":
                continue
            if not sp.account_enabled:
                continue
            if not _has_active_credentials(sp):
                continue

            # If SP has credentials but no role assignments
            # or oauth2 grants, it may be stale.
            if sp.id not in active_sp_ids:
                findings.append(
                    Finding(
                        check_id=self.metadata.check_id,
                        status=Status.FAIL,
                        severity=self.metadata.severity,
                        resource_type=self.metadata.resource_type,
                        resource_id=sp.id,
                        title=(
                            f"SP with unused credentials: "
                            f"{sp.display_name}"
                        ),
                        description=(
                            f"Service principal '{sp.display_name}' "
                            "has active credentials but no app role "
                            "assignments or delegated permission grants."
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
                    title=(
                        "No stale SPs with unused credentials"
                    ),
                )
            )

        return findings
