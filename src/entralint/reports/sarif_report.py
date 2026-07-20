"""SARIF 2.1.0 report formatter.

Produces a Static Analysis Results Interchange Format (SARIF) v2.1.0
document suitable for upload to GitHub Code Scanning, Azure DevOps,
and other SARIF-consuming tools.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
import re
from typing import Any

from entralint.core.check import Finding, Severity, Status

# Map EntraLint severity → SARIF level
_SARIF_LEVEL: dict[str, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


def format_sarif(
    findings: list[Finding],
    *,
    check_metadata: dict[str, Any] | None = None,
) -> str:
    """Serialize findings to a SARIF 2.1.0 JSON string.

    Parameters
    ----------
    findings:
        The list of findings from a scan run.
    check_metadata:
        Optional mapping of check_id → CheckMetadata.model_dump()
        used to populate the SARIF ``rules`` array with full
        descriptions.  When ``None`` the rules are derived from
        the findings themselves.
    """
    rules_by_id: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in findings:
        # Skip PASS findings — SARIF only represents problems
        if finding.status == Status.PASS:
            continue

        rule_id = finding.check_id
        if rule_id not in rules_by_id:
            rules_by_id[rule_id] = _build_rule(finding, check_metadata)

        results.append(_build_result(finding, rule_id))

    sarif: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "EntraLint",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/entralint/entralint",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def _build_rule(
    finding: Finding,
    check_metadata: dict[str, Any] | None,
) -> dict[str, Any]:
    """Build a SARIF ``reportingDescriptor`` for a rule."""
    rule_id = finding.check_id

    # Try to pull richer description from metadata if available
    meta = (check_metadata or {}).get(rule_id, {})
    full_description = meta.get("description", finding.description)
    help_text = meta.get("risk", "")
    help_uri = meta.get("remediation", {}).get("url", "")

    rule: dict[str, Any] = {
        "id": rule_id,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": full_description},
        "defaultConfiguration": {
            "level": _SARIF_LEVEL.get(finding.severity.value, "warning"),
        },
        "properties": {
            "tags": ["security", "entra-id"],
        },
    }

    if help_text:
        rule["help"] = {"text": help_text}
    if help_uri:
        rule["helpUri"] = help_uri

    return rule


def _build_result(finding: Finding, rule_id: str) -> dict[str, Any]:
    """Build a SARIF ``result`` object from a finding."""
    level = _SARIF_LEVEL.get(finding.severity.value, "warning")

    # Map skipped/error statuses
    if finding.status == Status.ERROR:
        level = "error"
    elif finding.status in (
        Status.SKIPPED_PERMISSION,
        Status.SKIPPED_LICENSE,
        Status.SKIPPED_DEPENDENCY,
    ):
        level = "none"

    message_text = finding.description or finding.title
    if finding.remediation:
        message_text = f"{message_text}\n\nRemediation: {finding.remediation}"

    result: dict[str, Any] = {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": message_text},
        "locations": [
            {
                # GitHub Code Scanning requires a physicalLocation for every
                # result. Entra findings are not tied to source files, so we
                # emit a stable synthetic artifact URI representing the scanned
                # resource and keep the logicalLocation for human-readable detail.
                "physicalLocation": {
                    "artifactLocation": {"uri": _synthetic_uri(finding)},
                    "region": {"startLine": 1},
                },
                "logicalLocations": [
                    {
                        "name": finding.resource_id or "tenant",
                        "kind": finding.resource_type or "resource",
                    }
                ],
            }
        ],
    }

    return result


def _synthetic_uri(finding: Finding) -> str:
    """Build a stable, filesystem-safe virtual URI for a finding.

    Entra ID findings do not map to files in the repository, but GitHub Code
    Scanning still requires ``physicalLocation.artifactLocation.uri``. We derive
    a deterministic path from the resource type and id so related findings group
    together and alerts remain stable across scans.
    """
    resource_type = (finding.resource_type or "tenant").strip("/")
    resource_id = finding.resource_id or "tenant"
    raw = f"{resource_type}/{resource_id}"
    safe = re.sub(r"[^A-Za-z0-9._/-]", "_", raw).strip("/")
    return f"entra/{safe or 'tenant'}"
