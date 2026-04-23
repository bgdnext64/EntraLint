"""Baseline snapshot management for EntraLint.

A baseline is a JSON file recording the fingerprint of every FAIL finding
from a specific scan.  Subsequent scans can compare against it to classify
findings as NEW, EXISTING (already present in baseline), or RESOLVED
(in baseline but no longer found).
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from entralint.core.check import Finding, Status

# ── Default file name ────────────────────────────────────────

DEFAULT_BASELINE_FILE = ".entralint-baseline.json"


# ── Models ───────────────────────────────────────────────────


class BaselineEntry(BaseModel):
    """One finding's fingerprint stored in the baseline."""

    check_id: str
    resource_id: str
    fingerprint: str
    severity: str
    title: str


class BaselineSnapshot(BaseModel):
    """A full baseline file."""

    tool: str = "entralint"
    version: str = "0.1.0"
    created_at: str = ""
    entries: list[BaselineEntry] = Field(default_factory=list)


class BaselineDelta(BaseModel):
    """Result of comparing a current scan against a baseline."""

    new: list[Finding] = Field(default_factory=list)
    existing: list[Finding] = Field(default_factory=list)
    resolved: list[BaselineEntry] = Field(default_factory=list)


# ── Fingerprinting ───────────────────────────────────────────


def _fingerprint(finding: Finding) -> str:
    """Produce a stable hash for a finding based on its identity fields.

    The fingerprint uses (check_id, resource_type, resource_id) so that
    changes in title/description wording don't break the match.
    """
    key = f"{finding.check_id}|{finding.resource_type}|{finding.resource_id}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


# ── Save / Load ──────────────────────────────────────────────


def save_baseline(findings: list[Finding], path: Path | str) -> Path:
    """Create a baseline file from the current scan's FAIL findings.

    Only FAIL findings are stored — PASS, SKIP, and ERROR are ignored.
    Returns the path written.

    The ``path`` is resolved and its parent directory must already exist,
    which makes obvious typos and directory-traversal style inputs fail
    fast instead of silently writing to an unexpected location.
    """
    resolved = Path(path).expanduser().resolve()
    if not resolved.parent.exists():
        raise ValueError(
            f"Baseline parent directory does not exist: {resolved.parent}"
        )
    if resolved.exists() and not resolved.is_file():
        raise ValueError(f"Baseline path is not a file: {resolved}")

    fail_findings = [f for f in findings if f.status == Status.FAIL]

    entries = [
        BaselineEntry(
            check_id=f.check_id,
            resource_id=f.resource_id,
            fingerprint=_fingerprint(f),
            severity=f.severity.value,
            title=f.title,
        )
        for f in fail_findings
    ]

    snapshot = BaselineSnapshot(
        created_at=datetime.now(UTC).isoformat(),
        entries=entries,
    )

    resolved.write_text(
        json.dumps(snapshot.model_dump(), indent=2),
        encoding="utf-8",
    )
    return resolved


def load_baseline(path: Path | str) -> BaselineSnapshot:
    """Load a baseline file.  Raises FileNotFoundError / ValueError."""
    path = Path(path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    return BaselineSnapshot.model_validate(raw)


# ── Comparison ───────────────────────────────────────────────


def compare(
    findings: list[Finding],
    baseline: BaselineSnapshot,
) -> BaselineDelta:
    """Compare current scan findings against a baseline.

    Returns a delta with three buckets:
    - **new**: FAIL findings not present in the baseline.
    - **existing**: FAIL findings already in the baseline.
    - **resolved**: baseline entries no longer appearing as FAIL.
    """
    # Build a set of fingerprints from the baseline for O(1) lookup.
    baseline_fps: dict[str, BaselineEntry] = {
        e.fingerprint: e for e in baseline.entries
    }

    current_fail = [f for f in findings if f.status == Status.FAIL]
    current_fps: set[str] = set()

    new: list[Finding] = []
    existing: list[Finding] = []

    for finding in current_fail:
        fp = _fingerprint(finding)
        current_fps.add(fp)
        if fp in baseline_fps:
            existing.append(finding)
        else:
            new.append(finding)

    # Resolved = in baseline but not in current failures.
    resolved = [
        entry for fp, entry in baseline_fps.items() if fp not in current_fps
    ]

    return BaselineDelta(new=new, existing=existing, resolved=resolved)


# ── Helpers for JSON serialization ───────────────────────────


def delta_summary(delta: BaselineDelta) -> dict[str, Any]:
    """Summary dict suitable for JSON/console output."""
    return {
        "new_findings": len(delta.new),
        "existing_findings": len(delta.existing),
        "resolved_findings": len(delta.resolved),
    }
