"""Check: Ensure email OTP authentication is reviewed."""

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

_METADATA_PATH = Path(__file__).parent / "auth_email_otp_enabled.metadata.json"


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


class AuthEmailOtpEnabled(BaseCheck):
    """Flags tenants where email OTP is enabled for guest authentication."""

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
        for cfg in configs:
            if cfg.get("id") == "Email" and cfg.get("state") == "enabled":
                return [Finding(
                    check_id=self.metadata.check_id,
                    check_version=self.metadata.check_version,
                    status=Status.FAIL,
                    severity=self.metadata.severity,
                    resource_type=self.metadata.resource_type,
                    resource_id="tenant-wide",
                    title="Email OTP authentication is enabled",
                    description=(
                        "Email one-time passcode authentication is enabled. "
                        "This method relies on the security of the guest's email "
                        "account, which may lack MFA protection."
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
            title="Email OTP authentication is not enabled",
            description="Email one-time passcode authentication is not enabled.",
        )]
