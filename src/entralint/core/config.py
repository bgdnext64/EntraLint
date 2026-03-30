"""Configuration file loading and validation for EntraLint."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class SuppressionRule(BaseModel):
    """A single check suppression entry."""

    check: str
    reason: str = ""


class SeverityOverride(BaseModel):
    """Override the severity of a specific check."""

    severity: str  # validated at apply-time against Severity enum


class EntraLintConfig(BaseModel):
    """Root configuration model for .entralint.yaml."""

    fail_on: str | None = None
    include_categories: list[str] = Field(default_factory=list)
    exclude_checks: list[str] = Field(default_factory=list)
    suppress: list[SuppressionRule] = Field(default_factory=list)
    overrides: dict[str, SeverityOverride] = Field(default_factory=dict)
    baseline: str | None = None


# Default filenames to search for, in priority order.
_CONFIG_FILENAMES = [
    ".entralint.yaml",
    ".entralint.yml",
    "entralint.yaml",
    "entralint.yml",
]


def discover_config(start: Path | None = None) -> Path | None:
    """Walk up from *start* (default: cwd) looking for a config file.

    Returns the first matching path, or ``None``.
    """
    current = (start or Path.cwd()).resolve()
    for _ in range(50):  # safety bound
        for name in _CONFIG_FILENAMES:
            candidate = current / name
            if candidate.is_file():
                return candidate
        parent = current.parent
        if parent == current:
            break
        current = parent
    return None


def load_config(path: Path) -> EntraLintConfig:
    """Parse and validate a config file.

    Raises ``ValueError`` for malformed YAML or invalid schema.
    """
    text = path.read_text(encoding="utf-8")
    raw = yaml.safe_load(text)
    if raw is None:
        return EntraLintConfig()
    if not isinstance(raw, dict):
        msg = f"Config must be a YAML mapping, got {type(raw).__name__}"
        raise ValueError(msg)
    return EntraLintConfig.model_validate(raw)


def load_config_auto(
    explicit_path: str | None = None,
    *,
    disabled: bool = False,
) -> EntraLintConfig | None:
    """High-level helper used by the CLI.

    * If *disabled* (``--no-config``), returns ``None``.
    * If *explicit_path* is given, loads it (raises on error).
    * Otherwise discovers and loads automatically (returns ``None`` if no file found).
    """
    if disabled:
        return None
    if explicit_path:
        return load_config(Path(explicit_path))
    found = discover_config()
    if found is None:
        return None
    return load_config(found)
