"""EntraLint CLI application — built with Typer + Rich."""

from __future__ import annotations

import sys
from typing import Annotated

import typer
from rich.console import Console

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import entralint
from entralint.cli.commands import cache, config, login, report, scan

console = Console()

app = typer.Typer(
    name="entralint",
    help="Lint your Entra ID. Fix before they breach.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

# Register sub-commands
app.command()(scan.scan)
app.command(name="scan-all")(scan.scan_all)
app.command()(login.login)
app.command()(report.report)
app.command()(config.config)
app.command()(cache.cache)


@app.command()
def version() -> None:
    """Show the EntraLint version."""
    console.print(f"EntraLint v{entralint.__version__}")


@app.command(name="list-checks")
def list_checks(
    category: Annotated[
        str | None, typer.Option(help="Filter by check category")
    ] = None,
    severity: Annotated[
        str | None, typer.Option(help="Filter by severity (critical,high,medium,low)")
    ] = None,
) -> None:
    """List available security checks."""
    from pathlib import Path

    from entralint.cli.output import display_check_list
    from entralint.core.config import load_config_auto
    from entralint.core.engine import CheckEngine

    cfg = load_config_auto()
    custom_dirs = (
        [Path(d) for d in cfg.custom_checks_dirs]
        if cfg and cfg.custom_checks_dirs
        else None
    )
    engine = CheckEngine(custom_checks_dirs=custom_dirs)
    checks = engine.discover()

    severity_list = [s.strip() for s in severity.split(",")] if severity else None
    if severity_list or category:
        checks = engine.filter_checks(severity=severity_list, category=category)

    display_check_list(checks)


@app.command(name="list-frameworks")
def list_frameworks() -> None:
    """List available compliance frameworks."""
    console.print("[bold]Available frameworks:[/bold]")
    console.print("  - CIS Microsoft 365 Foundations Benchmark v5")
    console.print("  - CISA SCuBA Entra ID Baseline (BOD 25-01)")
    console.print("  - NIST 800-53")


def _explain_check(check_id: str) -> None:
    """Look up a check by ID and display its full metadata."""
    from pathlib import Path

    from entralint.cli.output import display_check_detail
    from entralint.core.config import load_config_auto
    from entralint.core.engine import CheckEngine

    cfg = load_config_auto()
    custom_dirs = (
        [Path(d) for d in cfg.custom_checks_dirs]
        if cfg and cfg.custom_checks_dirs
        else None
    )
    engine = CheckEngine(custom_checks_dirs=custom_dirs)
    checks = engine.discover()
    matched = [c for c in checks if c.metadata.check_id == check_id]

    if not matched:
        console.print(f"[red]Check not found:[/red] {check_id}")
        raise typer.Exit(code=1)

    display_check_detail(matched[0].metadata)


@app.command(name="show-check")
def show_check(
    check_id: Annotated[str, typer.Argument(help="The check ID to display")],
) -> None:
    """Show full details for a specific check."""
    _explain_check(check_id)


@app.command()
def explain(
    check_id: Annotated[str, typer.Argument(help="The check ID to explain")],
) -> None:
    """Print full metadata, risk, remediation, and framework mappings for a check."""
    _explain_check(check_id)
