"""Check: Ensure persistent browser sessions are restricted."""

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

_METADATA_PATH = Path(__file__).parent / "ca_persistent_browser.metadata.json"


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


class CaPersistentBrowser(BaseCheck):
    """Checks for a CA policy restricting persistent browser sessions."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        for policy in context.conditional_access_policies:
            if policy.state != "enabled":
                continue

            sc = policy.session_controls
            if sc is None:
                continue

            # Check persistent browser set to "never"
            pb = sc.persistent_browser
            if pb and pb.get("mode", "").lower() == "never":
                return [
                    Finding(
                        check_id=self.metadata.check_id,
                        check_version=self.metadata.check_version,
                        status=Status.PASS,
                        severity=self.metadata.severity,
                        resource_type=self.metadata.resource_type,
                        resource_id=policy.id,
                        title="Persistent browser sessions restricted",
                        description=(
                            f"Policy '{policy.display_name}' disables "
                            f"persistent browser sessions."
                        ),
                    )
                ]

            # Check sign-in frequency is configured
            sif = sc.sign_in_frequency
            if sif and sif.get("isEnabled", "true").lower() != "false":
                return [
                    Finding(
                        check_id=self.metadata.check_id,
                        check_version=self.metadata.check_version,
                        status=Status.PASS,
                        severity=self.metadata.severity,
                        resource_type=self.metadata.resource_type,
                        resource_id=policy.id,
                        title="Sign-in frequency configured",
                        description=(
                            f"Policy '{policy.display_name}' enforces "
                            f"sign-in frequency controls."
                        ),
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
                title="No persistent browser session restriction",
                description=(
                    "No enabled Conditional Access policy restricts "
                    "persistent browser sessions or enforces sign-in "
                    "frequency. Sessions may persist indefinitely on "
                    "unmanaged or shared devices."
                ),
                remediation=self.metadata.remediation.recommendation,
                frameworks=self.metadata.frameworks,
            )
        ]
