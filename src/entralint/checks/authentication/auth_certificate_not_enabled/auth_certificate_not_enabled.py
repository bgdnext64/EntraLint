"""Check: Ensure certificate-based authentication is enabled."""

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

_METADATA_PATH = Path(__file__).parent / "auth_certificate_not_enabled.metadata.json"


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


class AuthCertificateNotEnabled(BaseCheck):
    """Flags tenants where certificate-based authentication is not enabled."""

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
            if cfg.get("id") == "X509Certificate" and cfg.get("state") == "enabled":
                return [Finding(
                    check_id=self.metadata.check_id,
                    check_version=self.metadata.check_version,
                    status=Status.PASS,
                    severity=self.metadata.severity,
                    resource_type=self.metadata.resource_type,
                    resource_id="tenant-wide",
                    title="Certificate-based authentication is enabled",
                    description=(
                        "X.509 certificate-based authentication"
                        " is enabled, providing phishing-resistant"
                        " authentication."
                    ),
                )]

        return [Finding(
            check_id=self.metadata.check_id,
            check_version=self.metadata.check_version,
            status=Status.FAIL,
            severity=self.metadata.severity,
            resource_type=self.metadata.resource_type,
            resource_id="tenant-wide",
            title="Certificate-based authentication is not enabled",
            description=(
                "X.509 certificate-based authentication is not"
                " enabled. Consider enabling CBA for"
                " phishing-resistant authentication"
                " alongside FIDO2."
            ),
            remediation=self.metadata.remediation.recommendation,
        )]
