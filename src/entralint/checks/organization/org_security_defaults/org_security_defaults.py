"""Check: Ensure Security Defaults status is appropriate for the tenant."""

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
    Path(__file__).parent / "org_security_defaults.metadata.json"
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
    )


class OrgSecurityDefaults(BaseCheck):
    """Checks Security Defaults status relative to CA policy usage."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        sd_policy = context.security_defaults_policy
        sd_enabled = sd_policy.get("isEnabled", False)
        has_ca_policies = bool(context.conditional_access_policies)

        if has_ca_policies and not sd_enabled:
            # Best practice: CA policies active, Security Defaults off
            return [
                Finding(
                    check_id=self.metadata.check_id,
                    check_version=self.metadata.check_version,
                    status=Status.PASS,
                    severity=self.metadata.severity,
                    resource_type=self.metadata.resource_type,
                    resource_id="tenant-wide",
                    title="Security Defaults disabled, CA policies active",
                    description=(
                        "Security Defaults are correctly disabled. "
                        "Conditional Access policies provide granular control."
                    ),
                )
            ]

        if not has_ca_policies and sd_enabled:
            # Acceptable: no CA but Security Defaults provides baseline
            return [
                Finding(
                    check_id=self.metadata.check_id,
                    check_version=self.metadata.check_version,
                    status=Status.PASS,
                    severity=self.metadata.severity,
                    resource_type=self.metadata.resource_type,
                    resource_id="tenant-wide",
                    title="Security Defaults enabled (no CA policies)",
                    description=(
                        "Security Defaults provide baseline MFA protection. "
                        "Consider migrating to Conditional Access for "
                        "granular policy control."
                    ),
                )
            ]

        if not has_ca_policies and not sd_enabled:
            # Worst case: no protection at all
            return [
                Finding(
                    check_id=self.metadata.check_id,
                    check_version=self.metadata.check_version,
                    status=Status.FAIL,
                    severity=Severity.CRITICAL,
                    resource_type=self.metadata.resource_type,
                    resource_id="tenant-wide",
                    title="No MFA enforcement — Security Defaults and CA both disabled",
                    description=(
                        "Neither Security Defaults nor Conditional Access "
                        "policies are configured. The tenant has NO MFA "
                        "enforcement. Enable Security Defaults immediately "
                        "or configure Conditional Access policies."
                    ),
                    remediation=self.metadata.remediation.recommendation,
                    frameworks=self.metadata.frameworks,
                )
            ]

        # CA policies exist but Security Defaults still on
        return [
            Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.FAIL,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id="tenant-wide",
                title="Security Defaults enabled alongside CA policies",
                description=(
                    "Security Defaults are enabled but Conditional Access "
                    "policies also exist. These are mutually exclusive — "
                    "disable Security Defaults to let CA policies take effect."
                ),
                remediation=self.metadata.remediation.recommendation,
                frameworks=self.metadata.frameworks,
            )
        ]
