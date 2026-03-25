"""JSON report formatter."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from entralint.core.check import Finding


def format_json(findings: list[Finding], *, indent: int = 2) -> str:
    """Serialize findings to a structured JSON report.

    Returns a JSON string with a top-level envelope containing
    metadata and the findings array.
    """
    report: dict[str, Any] = {
        "tool": "entralint",
        "version": "0.1.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "summary": _build_summary(findings),
        "findings": [f.model_dump(mode="json") for f in findings],
    }
    return json.dumps(report, indent=indent)


def _build_summary(findings: list[Finding]) -> dict[str, int]:
    from entralint.core.check import Status

    total = len(findings)
    passed = sum(1 for f in findings if f.status == Status.PASS)
    failed = sum(1 for f in findings if f.status == Status.FAIL)
    skipped = sum(
        1
        for f in findings
        if f.status
        in (Status.SKIPPED_LICENSE, Status.SKIPPED_PERMISSION, Status.SKIPPED_DEPENDENCY)
    )
    errors = sum(1 for f in findings if f.status == Status.ERROR)
    return {
        "total": total,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "errors": errors,
    }
