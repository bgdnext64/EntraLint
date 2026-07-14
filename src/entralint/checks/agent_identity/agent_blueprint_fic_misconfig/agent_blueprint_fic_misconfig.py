"""Check: Ensure agent blueprint federated credentials are securely configured."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

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
    Path(__file__).parent / "agent_blueprint_fic_misconfig.metadata.json"
)

# The audience Entra expects for workload-identity token exchange.
_EXPECTED_AUDIENCE = "api://azureadtokenexchange"


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


def _fic_problems(fic: dict[str, Any]) -> list[str]:
    """Return a list of human-readable problems for a single FIC entry."""
    problems: list[str] = []

    subject = str(fic.get("subject", "") or "").strip()
    if not subject or subject == "*":
        problems.append("subject is empty or a wildcard")

    issuer = str(fic.get("issuer", "") or "").strip()
    if not issuer:
        problems.append("issuer is empty")
    elif not issuer.lower().startswith("https://"):
        problems.append("issuer is not HTTPS")

    audiences = fic.get("audiences") or []
    normalized = {str(a).strip().lower() for a in audiences}
    if not normalized:
        problems.append("audience is missing")
    elif _EXPECTED_AUDIENCE not in normalized:
        problems.append(
            "audience does not include api://AzureADTokenExchange"
        )

    return problems


class AgentBlueprintFicMisconfig(BaseCheck):
    """Flags agent blueprints with insecure federated identity credentials."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        findings: list[Finding] = []

        for bp in context.agent_identity_blueprints:
            for fic in bp.federated_identity_credentials:
                problems = _fic_problems(fic)
                if not problems:
                    continue
                fic_name = str(fic.get("name", "") or "<unnamed>")
                findings.append(Finding(
                    check_id=self.metadata.check_id,
                    check_version=self.metadata.check_version,
                    status=Status.FAIL,
                    severity=self.metadata.severity,
                    resource_type=self.metadata.resource_type,
                    resource_id=bp.id,
                    title=(
                        f"Blueprint '{bp.display_name}' has a misconfigured "
                        f"federated credential"
                    ),
                    description=(
                        f"Federated identity credential '{fic_name}' is "
                        f"insecurely configured: {'; '.join(problems)}."
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
                title="No misconfigured agent blueprint federated credentials",
            ))

        return findings
