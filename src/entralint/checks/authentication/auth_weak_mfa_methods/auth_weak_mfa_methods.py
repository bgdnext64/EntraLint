"""Check: Ensure weak MFA methods (SMS, voice) are disabled."""

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

_METADATA_PATH = Path(__file__).parent / "auth_weak_mfa_methods.metadata.json"

# Authentication method IDs considered weak
WEAK_METHOD_IDS = {"Sms", "Voice"}


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


class AuthWeakMfaMethods(BaseCheck):
    """Flags tenants where SMS or voice MFA methods are enabled."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        policy = context.authentication_methods_policy
        if not policy:
            return self.skip(
                "Authentication methods policy not available",
                status=Status.SKIPPED_PERMISSION,
            )

        configs = policy.get("authenticationMethodConfigurations", [])
        enabled_weak: list[str] = []
        for cfg in configs:
            method_id = cfg.get("id", "")
            state = cfg.get("state", "disabled")
            if method_id in WEAK_METHOD_IDS and state == "enabled":
                enabled_weak.append(method_id)

        if enabled_weak:
            return [Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.FAIL,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id="tenant-wide",
                title=f"Weak MFA methods enabled: {', '.join(sorted(enabled_weak))}",
                description=(
                    f"The following weak authentication methods are "
                    f"enabled: {', '.join(sorted(enabled_weak))}. "
                    f"SMS and voice calls are vulnerable to SIM-swap "
                    f"and SS7 interception attacks."
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
            title="Weak MFA methods (SMS, voice) are disabled",
            description="Neither SMS nor voice call authentication methods are enabled.",
        )]
