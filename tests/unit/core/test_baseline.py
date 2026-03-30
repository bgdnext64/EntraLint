"""Tests for baseline snapshot management."""

from __future__ import annotations

import json
from pathlib import Path  # noqa: TC003

import pytest

from entralint.core.baseline import (
    BaselineDelta,
    BaselineEntry,
    BaselineSnapshot,
    _fingerprint,
    compare,
    delta_summary,
    load_baseline,
    save_baseline,
)
from entralint.core.check import Finding, Severity, Status

# ── Helpers ──────────────────────────────────────────────────


def _fail(
    check_id: str = "entraid_ca_001",
    resource_id: str = "policy-1",
    **kwargs,
) -> Finding:
    return Finding(
        check_id=check_id,
        status=Status.FAIL,
        severity=Severity.HIGH,
        resource_type="ConditionalAccessPolicy",
        resource_id=resource_id,
        title=f"Fail: {check_id}",
        **kwargs,
    )


def _pass(check_id: str = "entraid_ca_001") -> Finding:
    return Finding(
        check_id=check_id,
        status=Status.PASS,
        severity=Severity.HIGH,
        resource_type="ConditionalAccessPolicy",
        resource_id="tenant",
        title=f"Pass: {check_id}",
    )


# ── Fingerprint ──────────────────────────────────────────────


def test_fingerprint_stable():
    f = _fail()
    assert _fingerprint(f) == _fingerprint(f)


def test_fingerprint_same_identity():
    f1 = _fail(check_id="ca_001", resource_id="r1")
    f2 = Finding(
        check_id="ca_001",
        status=Status.FAIL,
        severity=Severity.HIGH,
        resource_type="ConditionalAccessPolicy",
        resource_id="r1",
        title="Different title text",
    )
    assert _fingerprint(f1) == _fingerprint(f2)


def test_fingerprint_different_resource():
    f1 = _fail(check_id="ca_001", resource_id="r1")
    f2 = _fail(check_id="ca_001", resource_id="r2")
    assert _fingerprint(f1) != _fingerprint(f2)


def test_fingerprint_different_check():
    f1 = _fail(check_id="ca_001", resource_id="r1")
    f2 = _fail(check_id="ca_002", resource_id="r1")
    assert _fingerprint(f1) != _fingerprint(f2)


# ── Save / Load ──────────────────────────────────────────────


def test_save_baseline(tmp_path: Path):
    findings = [_fail(), _pass(), _fail(resource_id="policy-2")]
    path = save_baseline(findings, tmp_path / "baseline.json")
    assert path.exists()

    raw = json.loads(path.read_text())
    assert raw["tool"] == "entralint"
    assert len(raw["entries"]) == 2  # only FAILs saved


def test_load_baseline(tmp_path: Path):
    findings = [_fail(), _fail(resource_id="policy-2")]
    save_baseline(findings, tmp_path / "baseline.json")

    snap = load_baseline(tmp_path / "baseline.json")
    assert isinstance(snap, BaselineSnapshot)
    assert len(snap.entries) == 2


def test_load_missing_file(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        load_baseline(tmp_path / "nonexistent.json")


def test_roundtrip_preserves_fingerprints(tmp_path: Path):
    f1 = _fail(check_id="ca_001", resource_id="r1")
    f2 = _fail(check_id="ca_002", resource_id="r2")
    save_baseline([f1, f2], tmp_path / "b.json")
    snap = load_baseline(tmp_path / "b.json")

    fps = {e.fingerprint for e in snap.entries}
    assert _fingerprint(f1) in fps
    assert _fingerprint(f2) in fps


# ── Compare ──────────────────────────────────────────────────


def test_compare_all_new():
    baseline = BaselineSnapshot(entries=[])
    findings = [_fail(resource_id="r1"), _fail(resource_id="r2")]
    delta = compare(findings, baseline)
    assert len(delta.new) == 2
    assert len(delta.existing) == 0
    assert len(delta.resolved) == 0


def test_compare_all_existing():
    f1 = _fail(resource_id="r1")
    f2 = _fail(resource_id="r2")
    entries = [
        BaselineEntry(
            check_id=f.check_id,
            resource_id=f.resource_id,
            fingerprint=_fingerprint(f),
            severity=f.severity.value,
            title=f.title,
        )
        for f in [f1, f2]
    ]
    baseline = BaselineSnapshot(entries=entries)
    delta = compare([f1, f2, _pass()], baseline)
    assert len(delta.new) == 0
    assert len(delta.existing) == 2
    assert len(delta.resolved) == 0


def test_compare_resolved():
    f1 = _fail(resource_id="r1")
    entry = BaselineEntry(
        check_id=f1.check_id,
        resource_id=f1.resource_id,
        fingerprint=_fingerprint(f1),
        severity=f1.severity.value,
        title=f1.title,
    )
    baseline = BaselineSnapshot(entries=[entry])
    # Current scan: f1 is now passing (not in FAIL findings)
    delta = compare([_pass()], baseline)
    assert len(delta.new) == 0
    assert len(delta.existing) == 0
    assert len(delta.resolved) == 1


def test_compare_mixed():
    f_old = _fail(check_id="ca_001", resource_id="r1")
    f_new = _fail(check_id="ca_002", resource_id="r2")
    f_gone = _fail(check_id="ca_003", resource_id="r3")

    entries = [
        BaselineEntry(
            check_id=f.check_id,
            resource_id=f.resource_id,
            fingerprint=_fingerprint(f),
            severity=f.severity.value,
            title=f.title,
        )
        for f in [f_old, f_gone]
    ]
    baseline = BaselineSnapshot(entries=entries)

    # Current: f_old still fails, f_new is new, f_gone is resolved
    delta = compare([f_old, f_new, _pass()], baseline)
    assert len(delta.new) == 1
    assert delta.new[0].check_id == "ca_002"
    assert len(delta.existing) == 1
    assert delta.existing[0].check_id == "ca_001"
    assert len(delta.resolved) == 1
    assert delta.resolved[0].check_id == "ca_003"


def test_compare_ignores_pass_findings():
    baseline = BaselineSnapshot(entries=[])
    findings = [_pass(), _pass()]
    delta = compare(findings, baseline)
    assert len(delta.new) == 0
    assert len(delta.existing) == 0


# ── delta_summary ────────────────────────────────────────────


def test_delta_summary():
    delta = BaselineDelta(
        new=[_fail(resource_id="r1")],
        existing=[_fail(resource_id="r2"), _fail(resource_id="r3")],
        resolved=[
            BaselineEntry(
                check_id="old",
                resource_id="gone",
                fingerprint="abc",
                severity="HIGH",
                title="Gone",
            )
        ],
    )
    s = delta_summary(delta)
    assert s["new_findings"] == 1
    assert s["existing_findings"] == 2
    assert s["resolved_findings"] == 1


# ── End-to-end save/load/compare ────────────────────────────


def test_e2e_baseline_workflow(tmp_path: Path):
    """Simulate: save baseline -> change findings -> compare."""
    # Scan 1: two failures
    scan1 = [
        _fail(check_id="ca_001", resource_id="r1"),
        _fail(check_id="ca_002", resource_id="r2"),
        _pass(check_id="ca_003"),
    ]
    save_baseline(scan1, tmp_path / "b.json")

    # Scan 2: r1 fixed, r3 new, r2 still fails
    scan2 = [
        _pass(check_id="ca_001"),
        _fail(check_id="ca_002", resource_id="r2"),
        _fail(check_id="ca_003", resource_id="r3"),
    ]
    snap = load_baseline(tmp_path / "b.json")
    delta = compare(scan2, snap)

    assert len(delta.new) == 1  # r3
    assert delta.new[0].resource_id == "r3"
    assert len(delta.existing) == 1  # r2
    assert delta.existing[0].resource_id == "r2"
    assert len(delta.resolved) == 1  # r1
    assert delta.resolved[0].resource_id == "r1"
