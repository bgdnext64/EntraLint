"""Check: Detect non-GA privileged roles with excessive assignments."""

from __future__ import annotations

import json
from collections import Counter
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
    Path(__file__).parent / "role_high_priv_count.metadata.json"
)

# Global Admin is already covered by role_001
_GA_ROLE_ID = "62e90394-69f5-4237-9190-012177145e10"

# High-privilege role template IDs to monitor (excluding GA)
_HIGH_PRIV_ROLES = {
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Admin",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Admin",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Account Administrator",
}

_MAX_PER_ROLE = 5


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


class RoleHighPrivCount(BaseCheck):
    """Flags non-GA privileged roles with too many assignments."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        # Count assignments per high-priv role (exclude GA)
        role_counts: Counter[str] = Counter()
        for ra in context.role_assignments:
            role_id = ra.role_definition_id
            if role_id in _HIGH_PRIV_ROLES:
                role_counts[role_id] += 1

        findings: list[Finding] = []
        for role_id, count in role_counts.items():
            if count > _MAX_PER_ROLE:
                role_name = _HIGH_PRIV_ROLES[role_id]
                findings.append(Finding(
                    check_id=self.metadata.check_id,
                    check_version=self.metadata.check_version,
                    status=Status.FAIL,
                    severity=self.metadata.severity,
                    resource_type=self.metadata.resource_type,
                    resource_id=role_id,
                    title=(
                        f"Excessive {role_name} assignments: {count}"
                    ),
                    description=(
                        f"Role '{role_name}' has {count} assignments "
                        f"(max: {_MAX_PER_ROLE}). Reduce standing "
                        "access and use PIM for just-in-time "
                        "activation."
                    ),
                    remediation=self.metadata.remediation.recommendation,
                ))

        if not findings:
            findings.append(Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.PASS,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id="tenant",
                title="Privileged role assignment counts within limits",
                description=(
                    "All monitored privileged roles have 5 or fewer "
                    "assignments."
                ),
                remediation="",
            ))

        return findings
