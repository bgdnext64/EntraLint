"""Check: Ensure disabled service principals do not have active credentials."""

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
    Path(__file__).parent / "sp_disabled_with_creds.metadata.json"
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


class SpDisabledWithCreds(BaseCheck):
    """Flags disabled service principals that still have active credentials."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        findings: list[Finding] = []

        for sp in context.service_principals:
            if sp.account_enabled:
                continue

            has_creds = sp.password_credentials or sp.key_credentials
            if not has_creds:
                continue

            cred_count = len(sp.password_credentials) + len(sp.key_credentials)
            findings.append(Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.FAIL,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id=sp.id,
                title=(
                    f"Disabled SP with active credentials: "
                    f"{sp.display_name}"
                ),
                description=(
                    f"Service principal '{sp.display_name}' is disabled "
                    f"but has {cred_count} active credential(s). "
                    f"Remove credentials or delete the service principal."
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
                title="No disabled service principals with active credentials",
                description=(
                    "All disabled service principals have had their "
                    "credentials removed."
                ),
            ))

        return findings
