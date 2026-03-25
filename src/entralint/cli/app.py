"""EntraLint CLI application — built with Typer + Rich."""

from __future__ import annotations

from typing import Annotated

import typer
from rich.console import Console

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
    from entralint.cli.output import display_check_list
    from entralint.core.engine import CheckEngine

    engine = CheckEngine()
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


@app.command(name="show-check")
def show_check(
    check_id: Annotated[str, typer.Argument(help="The check ID to display")],
) -> None:
    """Show details for a specific check."""
    from entralint.core.engine import CheckEngine

    engine = CheckEngine()
    checks = engine.discover()
    matched = [c for c in checks if c.metadata.check_id == check_id]

    if not matched:
        console.print(f"[red]Check not found:[/red] {check_id}")
        raise typer.Exit(code=1)

    meta = matched[0].metadata
    console.print(f"[bold]{meta.check_id}[/bold] (v{meta.check_version})")
    console.print(f"  Title:    {meta.check_title}")
    console.print(f"  Severity: {meta.severity.value}")
    console.print(f"  Category: {meta.service_name}")
    console.print(f"  Risk:     {meta.risk}")
    if meta.remediation.recommendation:
        console.print(f"  Fix:      {meta.remediation.recommendation}")
    if meta.remediation.url:
        console.print(f"  Docs:     {meta.remediation.url}")
