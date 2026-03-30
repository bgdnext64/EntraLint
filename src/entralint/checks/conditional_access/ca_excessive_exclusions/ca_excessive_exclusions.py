"""Check: Review CA policies with excessive user exclusions."""

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
    Path(__file__).parent / "ca_excessive_exclusions.metadata.json"
)

_EXCLUSION_THRESHOLD = 5


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


class CaExcessiveExclusions(BaseCheck):
    """Flags CA policies with too many user/group exclusions."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        findings: list[Finding] = []

        for policy in context.conditional_access_policies:
            if policy.state not in ("enabled", "enabledForReportingButNotEnforced"):
                continue

            users = policy.conditions.users
            exclusion_count = (
                len(users.exclude_users) + len(users.exclude_groups)
            )
            if exclusion_count > _EXCLUSION_THRESHOLD:
                findings.append(
                    Finding(
                        check_id=self.metadata.check_id,
                        status=Status.FAIL,
                        severity=self.metadata.severity,
                        resource_type=self.metadata.resource_type,
                        resource_id=policy.id,
                        title=(
                            f"Excessive exclusions in policy: "
                            f"{policy.display_name}"
                        ),
                        description=(
                            f"Policy '{policy.display_name}' excludes "
                            f"{exclusion_count} users/groups "
                            f"(threshold: {_EXCLUSION_THRESHOLD})."
                        ),
                        remediation=self.metadata.remediation.recommendation,
                    )
                )

        if not findings:
            findings.append(
                Finding(
                    check_id=self.metadata.check_id,
                    status=Status.PASS,
                    severity=self.metadata.severity,
                    title="No CA policies with excessive exclusions",
                )
            )

        return findings
