"""Check: Ensure a custom banned password list is configured."""

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
    Path(__file__).parent / "auth_banned_passwords.metadata.json"
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


class AuthBannedPasswords(BaseCheck):
    """Checks for a custom banned password list."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        # The authentication methods policy may contain password
        # protection settings, or they may be in a separate
        # groupSettings endpoint. We check the auth methods policy
        # for any password-related configuration.
        policy = context.authentication_methods_policy

        # Look for password protection configuration
        # The Graph API returns this under different structures
        # depending on tenant configuration.
        auth_method_configs = policy.get(
            "authenticationMethodConfigurations", []
        )

        # Check for custom banned passwords in policy
        for config in auth_method_configs:
            if config.get("id", "") == "password":
                state = config.get("state", "")
                if state == "enabled":
                    return [
                        Finding(
                            check_id=self.metadata.check_id,
                            status=Status.PASS,
                            severity=self.metadata.severity,
                            title=(
                                "Password protection is configured"
                            ),
                        )
                    ]

        # If we can't determine from policy, check for custom
        # banned password indicators in the raw policy data
        if policy.get("enableBannedPasswordCheck"):
            return [
                Finding(
                    check_id=self.metadata.check_id,
                    status=Status.PASS,
                    severity=self.metadata.severity,
                    title="Custom banned password list enabled",
                )
            ]

        return [
            Finding(
                check_id=self.metadata.check_id,
                status=Status.FAIL,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                title="No custom banned password list detected",
                description=(
                    "No custom banned password list configuration "
                    "was found. Users may set passwords containing "
                    "organization-specific terms."
                ),
                remediation=self.metadata.remediation.recommendation,
            )
        ]
