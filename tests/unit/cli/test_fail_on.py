"""Tests for --fail-on flag and exit code logic."""

from entralint.core.check import (
    SEVERITY_RANK,
    Finding,
    Severity,
    Status,
)

# ---------------------------------------------------------------------------
# SEVERITY_RANK ordering tests
# ---------------------------------------------------------------------------

def test_severity_rank_ordering():
    """CRITICAL is the most severe (lowest rank)."""
    assert SEVERITY_RANK[Severity.CRITICAL] < SEVERITY_RANK[Severity.HIGH]
    assert SEVERITY_RANK[Severity.HIGH] < SEVERITY_RANK[Severity.MEDIUM]
    assert SEVERITY_RANK[Severity.MEDIUM] < SEVERITY_RANK[Severity.LOW]


def test_severity_rank_covers_all_values():
    for sev in Severity:
        assert sev in SEVERITY_RANK


# ---------------------------------------------------------------------------
# Helper to simulate the exit-code logic from scan()
# ---------------------------------------------------------------------------

def _compute_exit(findings: list[Finding], fail_on: str) -> int:
    """Mirror the exit-code logic in scan() for unit testing."""
    fail_on_lower = fail_on.lower()
    if fail_on_lower == "none":
        return 0

    threshold_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
    }
    threshold = threshold_map.get(fail_on_lower)
    if threshold is None:
        return 2  # invalid value

    threshold_rank = SEVERITY_RANK[threshold]
    has_failures = any(
        f.status == Status.FAIL and SEVERITY_RANK.get(f.severity, 99) <= threshold_rank
        for f in findings
    )
    return 1 if has_failures else 0


def _finding(severity: Severity, status: Status = Status.FAIL) -> Finding:
    return Finding(
        check_id="test_001",
        status=status,
        severity=severity,
        title="test finding",
    )


# ---------------------------------------------------------------------------
# --fail-on none → always exit 0
# ---------------------------------------------------------------------------

def test_fail_on_none_always_exits_zero():
    findings = [_finding(Severity.CRITICAL)]
    assert _compute_exit(findings, "none") == 0


def test_fail_on_none_case_insensitive():
    assert _compute_exit([_finding(Severity.CRITICAL)], "None") == 0
    assert _compute_exit([_finding(Severity.CRITICAL)], "NONE") == 0


# ---------------------------------------------------------------------------
# --fail-on critical → only critical triggers failure
# ---------------------------------------------------------------------------

def test_fail_on_critical_with_critical_finding():
    assert _compute_exit([_finding(Severity.CRITICAL)], "critical") == 1


def test_fail_on_critical_with_high_finding():
    assert _compute_exit([_finding(Severity.HIGH)], "critical") == 0


def test_fail_on_critical_with_medium_finding():
    assert _compute_exit([_finding(Severity.MEDIUM)], "critical") == 0


def test_fail_on_critical_with_low_finding():
    assert _compute_exit([_finding(Severity.LOW)], "critical") == 0


# ---------------------------------------------------------------------------
# --fail-on high → critical + high trigger failure
# ---------------------------------------------------------------------------

def test_fail_on_high_with_critical_finding():
    assert _compute_exit([_finding(Severity.CRITICAL)], "high") == 1


def test_fail_on_high_with_high_finding():
    assert _compute_exit([_finding(Severity.HIGH)], "high") == 1


def test_fail_on_high_with_medium_finding():
    assert _compute_exit([_finding(Severity.MEDIUM)], "high") == 0


def test_fail_on_high_with_low_finding():
    assert _compute_exit([_finding(Severity.LOW)], "high") == 0


# ---------------------------------------------------------------------------
# --fail-on medium (default) → critical + high + medium trigger failure
# ---------------------------------------------------------------------------

def test_fail_on_medium_with_critical():
    assert _compute_exit([_finding(Severity.CRITICAL)], "medium") == 1


def test_fail_on_medium_with_high():
    assert _compute_exit([_finding(Severity.HIGH)], "medium") == 1


def test_fail_on_medium_with_medium():
    assert _compute_exit([_finding(Severity.MEDIUM)], "medium") == 1


def test_fail_on_medium_with_low():
    assert _compute_exit([_finding(Severity.LOW)], "medium") == 0


# ---------------------------------------------------------------------------
# --fail-on low → everything triggers failure
# ---------------------------------------------------------------------------

def test_fail_on_low_with_low_finding():
    assert _compute_exit([_finding(Severity.LOW)], "low") == 1


def test_fail_on_low_with_critical():
    assert _compute_exit([_finding(Severity.CRITICAL)], "low") == 1


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_no_findings_always_passes():
    assert _compute_exit([], "low") == 0
    assert _compute_exit([], "critical") == 0


def test_only_pass_findings_no_failure():
    findings = [_finding(Severity.CRITICAL, status=Status.PASS)]
    assert _compute_exit(findings, "low") == 0


def test_skipped_findings_no_failure():
    findings = [
        Finding(
            check_id="test_001",
            status=Status.SKIPPED_PERMISSION,
            severity=Severity.CRITICAL,
            title="skipped",
        )
    ]
    assert _compute_exit(findings, "low") == 0


def test_mixed_findings_threshold_boundary():
    """With --fail-on high, a MEDIUM fail doesn't trigger but a HIGH does."""
    findings = [
        _finding(Severity.MEDIUM),
        _finding(Severity.LOW),
    ]
    assert _compute_exit(findings, "high") == 0
    findings.append(_finding(Severity.HIGH))
    assert _compute_exit(findings, "high") == 1


def test_invalid_fail_on_value():
    assert _compute_exit([], "banana") == 2
