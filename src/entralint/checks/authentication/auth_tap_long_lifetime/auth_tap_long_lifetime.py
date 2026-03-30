"""Check: Ensure Temporary Access Pass maximum lifetime is not excessive."""

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

_METADATA_PATH = Path(__file__).parent / "auth_tap_long_lifetime.metadata.json"

MAX_LIFETIME_MINUTES = 480  # 8 hours


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


class AuthTapLongLifetime(BaseCheck):
    """Flags tenants where TAP maximum lifetime exceeds 8 hours."""

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
            if cfg.get("id") != "TemporaryAccessPass":
                continue
            if cfg.get("state") != "enabled":
                return [Finding(
                    check_id=self.metadata.check_id,
                    check_version=self.metadata.check_version,
                    status=Status.PASS,
                    severity=self.metadata.severity,
                    resource_type=self.metadata.resource_type,
                    resource_id="tenant-wide",
                    title="Temporary Access Pass is not enabled",
                    description="TAP is not enabled, so excessive lifetime is not a concern.",
                )]

            max_life = cfg.get("maximumLifetimeInMinutes", 60)
            if max_life > MAX_LIFETIME_MINUTES:
                return [Finding(
                    check_id=self.metadata.check_id,
                    check_version=self.metadata.check_version,
                    status=Status.FAIL,
                    severity=self.metadata.severity,
                    resource_type=self.metadata.resource_type,
                    resource_id="tenant-wide",
                    title=(
                        f"TAP maximum lifetime is {max_life}"
                        f" minutes (exceeds {MAX_LIFETIME_MINUTES})"
                    ),
                    description=(
                        f"Temporary Access Pass maximum lifetime is set to "
                        f"{max_life} minutes, which exceeds the recommended "
                        f"maximum of {MAX_LIFETIME_MINUTES} minutes (8 hours). "
                        f"Long-lived TAPs increase the window for credential theft."
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
                title=f"TAP maximum lifetime is {max_life} minutes",
                description=(
                    f"Temporary Access Pass maximum lifetime"
                    f" ({max_life} min) is within acceptable"
                    " limits."
                ),
            )]

        # TAP not in configurations at all
        return [Finding(
            check_id=self.metadata.check_id,
            check_version=self.metadata.check_version,
            status=Status.PASS,
            severity=self.metadata.severity,
            resource_type=self.metadata.resource_type,
            resource_id="tenant-wide",
            title="Temporary Access Pass is not configured",
            description="TAP is not present in the authentication methods policy.",
        )]
