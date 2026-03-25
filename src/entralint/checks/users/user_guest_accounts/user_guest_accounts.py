"""Check: Review guest user accounts in the tenant."""

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

_METADATA_PATH = Path(__file__).parent / "user_guest_accounts.metadata.json"


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


class UserGuestAccounts(BaseCheck):
    """Reports on guest user accounts present in the tenant."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        guests = [u for u in context.users if u.user_type == "Guest"]

        if not guests:
            return [
                Finding(
                    check_id=self.metadata.check_id,
                    check_version=self.metadata.check_version,
                    status=Status.PASS,
                    severity=self.metadata.severity,
                    resource_type=self.metadata.resource_type,
                    resource_id="tenant-wide",
                    title="No guest users found",
                    description="No external guest accounts exist in the tenant.",
                )
            ]

        return [
            Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.FAIL,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id="tenant-wide",
                title=f"{len(guests)} guest user(s) found — review recommended",
                description=(
                    f"Found {len(guests)} guest (external) user account(s). "
                    "Review these accounts to ensure they are still needed "
                    "and have appropriate permissions."
                ),
                remediation=self.metadata.remediation.recommendation,
                frameworks=self.metadata.frameworks,
            )
        ]
