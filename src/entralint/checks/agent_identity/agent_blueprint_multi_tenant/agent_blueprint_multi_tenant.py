"""Check: Ensure agent blueprints are single-tenant."""

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
    Path(__file__).parent / "agent_blueprint_multi_tenant.metadata.json"
)

# signInAudience values that extend a blueprint beyond the home tenant.
NON_SINGLE_TENANT_AUDIENCES: dict[str, str] = {
    "azureadmultipleorgs": "multi-tenant (any Entra organization)",
    "azureadandpersonalmicrosoftaccount": (
        "multi-tenant and personal Microsoft accounts"
    ),
    "personalmicrosoftaccount": "personal Microsoft accounts only",
}


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


class AgentBlueprintMultiTenant(BaseCheck):
    """Flags agent blueprints whose signInAudience extends beyond the tenant."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        findings: list[Finding] = []

        for bp in context.agent_identity_blueprints:
            audience = (bp.sign_in_audience or "").strip().lower()
            label = NON_SINGLE_TENANT_AUDIENCES.get(audience)
            if label:
                findings.append(Finding(
                    check_id=self.metadata.check_id,
                    check_version=self.metadata.check_version,
                    status=Status.FAIL,
                    severity=self.metadata.severity,
                    resource_type=self.metadata.resource_type,
                    resource_id=bp.id,
                    title=(
                        f"Blueprint '{bp.display_name}' is not single-tenant"
                    ),
                    description=(
                        f"Agent blueprint has signInAudience "
                        f"'{bp.sign_in_audience}' ({label}). Agents derived "
                        f"from it can be provisioned or consented to beyond "
                        f"the home tenant."
                    ),
                    remediation=self.metadata.remediation.recommendation,
                    frameworks=self.metadata.frameworks,
                ))

        if not findings:
            findings.append(Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.PASS,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id="tenant-wide",
                title="All agent blueprints are single-tenant",
            ))

        return findings
