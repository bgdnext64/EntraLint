"""Check: Ensure device code flow is blocked via Conditional Access."""

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

_METADATA_PATH = Path(__file__).parent / "ca_device_code_flow.metadata.json"


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


class CaDeviceCodeFlow(BaseCheck):
    """Checks that device code flow is blocked by CA policy."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        for policy in context.conditional_access_policies:
            if policy.state != "enabled":
                continue

            client_types = [
                ct.lower()
                for ct in policy.conditions.client_app_types
            ]
            if "deviceCode" in policy.conditions.client_app_types or \
               "devicecode" in client_types:
                # Check if the policy blocks (denies) access
                gc = policy.grant_controls
                if gc and "block" in gc.built_in_controls:
                    return [
                        Finding(
                            check_id=self.metadata.check_id,
                            status=Status.PASS,
                            severity=self.metadata.severity,
                            title="Device code flow blocked by CA policy",
                            description=(
                                f"Policy '{policy.display_name}' blocks "
                                "device code authentication flow."
                            ),
                        )
                    ]

        return [
            Finding(
                check_id=self.metadata.check_id,
                status=Status.FAIL,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                title="Device code flow not blocked",
                description=(
                    "No enabled CA policy blocks the device code "
                    "authentication flow, which is commonly abused "
                    "in phishing attacks."
                ),
                remediation=self.metadata.remediation.recommendation,
            )
        ]
