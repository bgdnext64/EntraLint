"""Tests for EntraLint configuration loading and validation."""

from pathlib import Path

import pytest
import yaml

from entralint.core.config import (
    EntraLintConfig,
    SeverityOverride,
    SuppressionRule,
    discover_config,
    load_config,
    load_config_auto,
)

# ---------------------------------------------------------------------------
# EntraLintConfig model
# ---------------------------------------------------------------------------


def test_empty_config():
    cfg = EntraLintConfig()
    assert cfg.fail_on is None
    assert cfg.suppress == []
    assert cfg.overrides == {}
    assert cfg.exclude_checks == []
    assert cfg.include_categories == []
    assert cfg.baseline is None


def test_full_config():
    cfg = EntraLintConfig.model_validate({
        "fail_on": "high",
        "suppress": [
            {"check": "entraid_app_003", "reason": "accepted risk"},
        ],
        "overrides": {
            "entraid_app_002": {"severity": "low"},
        },
        "exclude_checks": ["entraid_sp_004"],
        "include_categories": ["conditional_access"],
        "baseline": ".entralint-baseline.json",
    })
    assert cfg.fail_on == "high"
    assert len(cfg.suppress) == 1
    assert cfg.suppress[0].check == "entraid_app_003"
    assert cfg.suppress[0].reason == "accepted risk"
    assert cfg.overrides["entraid_app_002"].severity == "low"
    assert cfg.exclude_checks == ["entraid_sp_004"]
    assert cfg.include_categories == ["conditional_access"]
    assert cfg.baseline == ".entralint-baseline.json"


def test_suppression_without_reason():
    cfg = EntraLintConfig.model_validate({
        "suppress": [{"check": "entraid_ca_001"}],
    })
    assert cfg.suppress[0].reason == ""


# ---------------------------------------------------------------------------
# load_config
# ---------------------------------------------------------------------------


def test_load_config_valid(tmp_path: Path):
    cfg_file = tmp_path / ".entralint.yaml"
    cfg_file.write_text(
        yaml.dump({
            "fail_on": "critical",
            "suppress": [{"check": "entraid_ca_001", "reason": "testing"}],
        }),
        encoding="utf-8",
    )
    cfg = load_config(cfg_file)
    assert cfg.fail_on == "critical"
    assert len(cfg.suppress) == 1


def test_load_config_empty_file(tmp_path: Path):
    cfg_file = tmp_path / ".entralint.yaml"
    cfg_file.write_text("", encoding="utf-8")
    cfg = load_config(cfg_file)
    assert cfg.fail_on is None


def test_load_config_invalid_type(tmp_path: Path):
    cfg_file = tmp_path / ".entralint.yaml"
    cfg_file.write_text("- just a list\n- not a mapping\n", encoding="utf-8")
    with pytest.raises(ValueError, match="YAML mapping"):
        load_config(cfg_file)


def test_load_config_overrides(tmp_path: Path):
    cfg_file = tmp_path / ".entralint.yaml"
    cfg_file.write_text(
        yaml.dump({
            "overrides": {
                "entraid_app_002": {"severity": "low"},
                "entraid_ca_001": {"severity": "HIGH"},
            },
        }),
        encoding="utf-8",
    )
    cfg = load_config(cfg_file)
    assert cfg.overrides["entraid_app_002"].severity == "low"
    assert cfg.overrides["entraid_ca_001"].severity == "HIGH"


# ---------------------------------------------------------------------------
# discover_config
# ---------------------------------------------------------------------------


def test_discover_config_in_cwd(tmp_path: Path):
    (tmp_path / ".entralint.yaml").write_text("fail_on: high\n")
    found = discover_config(start=tmp_path)
    assert found is not None
    assert found.name == ".entralint.yaml"


def test_discover_config_yml_extension(tmp_path: Path):
    (tmp_path / ".entralint.yml").write_text("fail_on: high\n")
    found = discover_config(start=tmp_path)
    assert found is not None
    assert found.name == ".entralint.yml"


def test_discover_config_without_dot(tmp_path: Path):
    (tmp_path / "entralint.yaml").write_text("fail_on: high\n")
    found = discover_config(start=tmp_path)
    assert found is not None
    assert found.name == "entralint.yaml"


def test_discover_config_prefers_dotfile(tmp_path: Path):
    """The dotted version has higher priority."""
    (tmp_path / ".entralint.yaml").write_text("fail_on: high\n")
    (tmp_path / "entralint.yaml").write_text("fail_on: low\n")
    found = discover_config(start=tmp_path)
    assert found is not None
    assert found.name == ".entralint.yaml"


def test_discover_config_walks_up(tmp_path: Path):
    (tmp_path / ".entralint.yaml").write_text("fail_on: high\n")
    child = tmp_path / "sub" / "deep"
    child.mkdir(parents=True)
    found = discover_config(start=child)
    assert found is not None
    assert found == tmp_path / ".entralint.yaml"


def test_discover_config_not_found(tmp_path: Path):
    found = discover_config(start=tmp_path)
    assert found is None


# ---------------------------------------------------------------------------
# load_config_auto
# ---------------------------------------------------------------------------


def test_load_config_auto_disabled():
    result = load_config_auto(disabled=True)
    assert result is None


def test_load_config_auto_explicit(tmp_path: Path):
    cfg_file = tmp_path / "custom.yaml"
    cfg_file.write_text("fail_on: critical\n", encoding="utf-8")
    cfg = load_config_auto(str(cfg_file))
    assert cfg is not None
    assert cfg.fail_on == "critical"


def test_load_config_auto_discovers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    (tmp_path / ".entralint.yaml").write_text("fail_on: high\n")
    monkeypatch.chdir(tmp_path)
    cfg = load_config_auto()
    assert cfg is not None
    assert cfg.fail_on == "high"


def test_load_config_auto_no_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.chdir(tmp_path)
    result = load_config_auto()
    assert result is None


# ---------------------------------------------------------------------------
# Config integration with findings (unit-level)
# ---------------------------------------------------------------------------


def test_suppress_filters_findings():
    """Simulate suppression: check IDs in suppress list should be removed."""
    from entralint.core.check import Finding, Severity, Status

    suppress = [
        SuppressionRule(check="entraid_app_003", reason="accepted"),
    ]
    exclude_set = {r.check for r in suppress}

    findings = [
        Finding(
            check_id="entraid_app_001", status=Status.FAIL,
            severity=Severity.HIGH, title="a",
        ),
        Finding(
            check_id="entraid_app_003", status=Status.FAIL,
            severity=Severity.MEDIUM, title="b",
        ),
        Finding(
            check_id="entraid_ca_001", status=Status.FAIL,
            severity=Severity.CRITICAL, title="c",
        ),
    ]
    filtered = [f for f in findings if f.check_id not in exclude_set]
    assert len(filtered) == 2
    assert all(f.check_id != "entraid_app_003" for f in filtered)


def test_severity_override_applied():
    """Simulate severity override."""
    from entralint.core.check import Finding, Severity, Status

    overrides = {"entraid_app_002": SeverityOverride(severity="low")}
    findings = [
        Finding(
            check_id="entraid_app_002", status=Status.FAIL,
            severity=Severity.MEDIUM, title="a",
        ),
        Finding(
            check_id="entraid_ca_001", status=Status.FAIL,
            severity=Severity.CRITICAL, title="b",
        ),
    ]

    for f in findings:
        override = overrides.get(f.check_id)
        if override:
            f.severity = Severity(override.severity.upper())

    assert findings[0].severity == Severity.LOW
    assert findings[1].severity == Severity.CRITICAL


def test_config_fail_on_overridden_by_cli():
    """CLI --fail-on should take precedence over config fail_on."""
    cfg = EntraLintConfig(fail_on="high")
    cli_fail_on = "critical"
    effective = cli_fail_on or cfg.fail_on or "medium"
    assert effective == "critical"


def test_config_fail_on_used_when_cli_none():
    """Config fail_on used when CLI doesn't specify."""
    cfg = EntraLintConfig(fail_on="high")
    cli_fail_on = None
    effective = cli_fail_on or cfg.fail_on or "medium"
    assert effective == "high"


def test_default_fail_on_when_no_config_no_cli():
    """Falls back to 'medium' when neither config nor CLI specified."""
    cli_fail_on = None
    cfg_fail_on = None
    effective = cli_fail_on or cfg_fail_on or "medium"
    assert effective == "medium"
