"""Check: Detect certificate credentials shared across agent identities."""

from __future__ import annotations

import json
from collections import defaultdict
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
    Path(__file__).parent / "agent_shared_credentials.metadata.json"
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


class AgentSharedCredentials(BaseCheck):
    """Flags a certificate thumbprint reused across multiple agents."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        # Map certificate thumbprint -> set of owning agent principals.
        # Keyed by a stable (kind, id) tuple so the same object listing a
        # credential twice is not miscounted as sharing.
        owners_by_thumbprint: dict[str, dict[tuple[str, str], str]] = (
            defaultdict(dict)
        )

        collections: list[tuple[str, list[Any]]] = [
            ("AgentIdentity", context.agent_identities),
            ("AgentIdentityBlueprint", context.agent_identity_blueprints),
        ]

        for kind, objects in collections:
            for obj in objects:
                for cred in obj.key_credentials:
                    thumbprint = cred.custom_key_identifier
                    if not thumbprint:
                        continue
                    owners_by_thumbprint[thumbprint][(kind, obj.id)] = (
                        obj.display_name or obj.id
                    )

        findings: list[Finding] = []

        for thumbprint, owners in owners_by_thumbprint.items():
            if len(owners) < 2:
                continue
            names = sorted(owners.values())
            findings.append(
                Finding(
                    check_id=self.metadata.check_id,
                    check_version=self.metadata.check_version,
                    status=Status.FAIL,
                    severity=self.metadata.severity,
                    resource_type=self.metadata.resource_type,
                    resource_id=thumbprint,
                    title=(
                        f"Certificate shared by {len(owners)} agent "
                        f"identities: {', '.join(names)}"
                    ),
                    description=(
                        f"The certificate with thumbprint "
                        f"'{thumbprint}' is registered on "
                        f"{len(owners)} distinct agent principals "
                        f"({', '.join(names)}). Shared credentials "
                        f"prevent per-agent accountability and make a "
                        f"single leaked secret compromise every agent "
                        f"that relies on it."
                    ),
                    remediation=self.metadata.remediation.recommendation,
                    raw_data={
                        "thumbprint": thumbprint,
                        "owners": [
                            {"type": kind, "id": obj_id, "name": name}
                            for (kind, obj_id), name in sorted(
                                owners.items()
                            )
                        ],
                    },
                )
            )

        if not findings:
            findings.append(
                Finding(
                    check_id=self.metadata.check_id,
                    check_version=self.metadata.check_version,
                    status=Status.PASS,
                    severity=self.metadata.severity,
                    resource_type=self.metadata.resource_type,
                    resource_id="tenant-wide",
                    title="No certificate credentials shared across agents",
                )
            )

        return findings
