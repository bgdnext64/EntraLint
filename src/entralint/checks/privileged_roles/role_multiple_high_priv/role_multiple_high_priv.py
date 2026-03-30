"""Check: Detect users with multiple high-privilege role assignments."""

from __future__ import annotations

import json
from collections import defaultdict
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

_METADATA_PATH = Path(__file__).parent / "role_multiple_high_priv.metadata.json"

# Well-known high-privilege role definition IDs
HIGH_PRIV_ROLES: dict[str, str] = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
}


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


class RoleMultipleHighPriv(BaseCheck):
    """Flags users holding multiple high-privilege directory roles."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        if not context.role_assignments:
            return self.skip(
                "No role assignments available",
                status=Status.SKIPPED_PERMISSION,
            )

        # Group high-priv assignments by principal
        principal_roles: dict[str, list[str]] = defaultdict(list)
        principal_names: dict[str, str] = {}
        for ra in context.role_assignments:
            if ra.role_definition_id in HIGH_PRIV_ROLES:
                principal_roles[ra.principal_id].append(
                    HIGH_PRIV_ROLES[ra.role_definition_id]
                )
                if ra.principal:
                    principal_names[ra.principal_id] = ra.principal.get(
                        "displayName", ra.principal_id
                    )

        findings: list[Finding] = []
        for pid, roles in sorted(principal_roles.items()):
            if len(roles) >= 2:
                name = principal_names.get(pid, pid)
                findings.append(Finding(
                    check_id=self.metadata.check_id,
                    check_version=self.metadata.check_version,
                    status=Status.FAIL,
                    severity=self.metadata.severity,
                    resource_type=self.metadata.resource_type,
                    resource_id=pid,
                    title=f"{name} holds {len(roles)} high-privilege roles",
                    description=(
                        f"User '{name}' has {len(roles)} high-privilege role "
                        f"assignments: {', '.join(sorted(roles))}. "
                        f"This violates the principle of least privilege."
                    ),
                    remediation=self.metadata.remediation.recommendation,
                ))

        if not findings:
            return [Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.PASS,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id="tenant-wide",
                title="No users hold multiple high-privilege roles",
                description=(
                    "No principal has two or more"
                    " high-privilege directory role"
                    " assignments."
                ),
            )]

        return findings
