"""Check: Ensure legacy authentication is blocked via Conditional Access."""

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

_METADATA_PATH = Path(__file__).parent / "ca_block_legacy_auth.metadata.json"

LEGACY_CLIENT_TYPES = {"exchangeActiveSync", "other"}


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


class CaBlockLegacyAuth(BaseCheck):
    """Checks that at least one enabled CA policy blocks legacy auth protocols."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        policies = context.conditional_access_policies

        for policy in policies:
            if policy.state != "enabled":
                continue

            # Policy must target all users
            users_include = policy.conditions.users.include_users
            if "All" not in users_include:
                continue

            # Check if it filters on legacy client app types
            client_types = set(policy.conditions.client_app_types)
            targets_legacy = bool(client_types & LEGACY_CLIENT_TYPES)
            if not targets_legacy:
                continue

            # Check if it blocks access (grant controls with block)
            if policy.grant_controls is None:
                continue
            if "block" in policy.grant_controls.built_in_controls:
                return [
                    Finding(
                        check_id=self.metadata.check_id,
                        check_version=self.metadata.check_version,
                        status=Status.PASS,
                        severity=self.metadata.severity,
                        resource_type=self.metadata.resource_type,
                        resource_id=policy.id,
                        title="Legacy authentication blocked",
                        description=(
                            f"Policy '{policy.display_name}' blocks legacy "
                            f"authentication protocols for all users."
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
                title="Legacy authentication not blocked",
                description=(
                    "No enabled Conditional Access policy blocks legacy auth "
                    "protocols (Exchange ActiveSync, IMAP, POP3). These protocols "
                    "bypass MFA entirely and are exploited in password spray attacks."
                ),
                remediation=self.metadata.remediation.recommendation,
                frameworks=self.metadata.frameworks,
            )
        ]
