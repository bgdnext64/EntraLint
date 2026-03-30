"""Check: Ensure Microsoft Authenticator number matching is enforced."""

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
    Path(__file__).parent / "auth_number_matching.metadata.json"
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


class AuthNumberMatching(BaseCheck):
    """Flags tenants where Authenticator number matching is not enforced."""

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
        authenticator_cfg = None
        for cfg in configs:
            if cfg.get("id") == "MicrosoftAuthenticator":
                authenticator_cfg = cfg
                break

        if not authenticator_cfg:
            return self.skip(
                "Microsoft Authenticator not configured in policy",
                status=Status.SKIPPED_PERMISSION,
            )

        if authenticator_cfg.get("state") != "enabled":
            return self.skip(
                "Microsoft Authenticator is disabled",
                status=Status.SKIPPED_PERMISSION,
            )

        # Check featureSettings for numberMatchingRequiredState
        feature_settings = authenticator_cfg.get("featureSettings", {})
        number_match = feature_settings.get(
            "numberMatchingRequiredState", {}
        )
        nm_state = number_match.get("state", "default")

        # "enabled" or "default" (default since May 2023 means on)
        if nm_state in ("enabled", "default"):
            return [Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.PASS,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id="MicrosoftAuthenticator",
                title="Number matching is enforced",
                description=(
                    f"Microsoft Authenticator number matching state: "
                    f"{nm_state}"
                ),
                remediation="",
            )]

        return [Finding(
            check_id=self.metadata.check_id,
            check_version=self.metadata.check_version,
            status=Status.FAIL,
            severity=self.metadata.severity,
            resource_type=self.metadata.resource_type,
            resource_id="MicrosoftAuthenticator",
            title="Number matching not enforced",
            description=(
                "Microsoft Authenticator number matching is disabled. "
                "Users can approve push notifications without entering "
                "a matching number, making MFA fatigue attacks possible."
            ),
            remediation=self.metadata.remediation.recommendation,
        )]
