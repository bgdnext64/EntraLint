"""Rich console output helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from entralint.core.check import BaseCheck, CheckMetadata, Finding

console = Console()


def display_check_list(checks: list[BaseCheck]) -> None:
    """Print a table of available checks."""
    if not checks:
        console.print("[dim]No checks found.[/dim]")
        return

    table = Table(title="EntraLint Security Checks", show_lines=False)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Severity", style="bold")
    table.add_column("Category")
    table.add_column("Title")

    severity_colors = {
        "CRITICAL": "red bold",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
    }

    for check in sorted(checks, key=lambda c: c.metadata.check_id):
        sev = check.metadata.severity.value
        color = severity_colors.get(sev, "white")
        table.add_row(
            check.metadata.check_id,
            f"[{color}]{sev}[/{color}]",
            check.metadata.service_name,
            check.metadata.check_title,
        )

    console.print(table)


def display_scan_summary(findings: list[Finding]) -> None:
    """Print the post-scan summary box."""
    from entralint.core.check import Status

    total = len(findings)
    passed = sum(1 for f in findings if f.status == Status.PASS)
    failed = sum(1 for f in findings if f.status == Status.FAIL)
    errors = sum(1 for f in findings if f.status == Status.ERROR)
    skipped = sum(
        1
        for f in findings
        if f.status
        in (Status.SKIPPED_LICENSE, Status.SKIPPED_PERMISSION, Status.SKIPPED_DEPENDENCY)
    )

    # Count unique check IDs to distinguish checks from findings.
    unique_checks = len({f.check_id for f in findings})

    console.print()
    console.rule("[bold]Summary[/bold]", characters="=")
    console.print(
        f"  Checks: {unique_checks}    "
        f"Findings: {total}    "
        f"[green]Passed: {passed}[/green]    "
        f"[red]Failed: {failed}[/red]    "
        f"[yellow]Skipped: {skipped}[/yellow]    "
        f"[red]Errors: {errors}[/red]"
    )
    console.print()


def display_baseline_delta(delta: object) -> None:
    """Print baseline comparison results.

    Accepts a BaselineDelta but typed as object to avoid circular imports.
    """
    new_count = len(delta.new)  # type: ignore[attr-defined]
    existing_count = len(delta.existing)  # type: ignore[attr-defined]
    resolved_count = len(delta.resolved)  # type: ignore[attr-defined]

    console.print(
        f"  [bold]Baseline:[/bold]  "
        f"[red]New: {new_count}[/red]    "
        f"[dim]Existing: {existing_count}[/dim]    "
        f"[green]Resolved: {resolved_count}[/green]"
    )
    console.print()


def display_check_detail(meta: CheckMetadata) -> None:
    """Print full metadata for a single check."""
    severity_colors = {
        "CRITICAL": "red bold",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
    }
    sev = meta.severity.value
    sev_style = severity_colors.get(sev, "white")

    # Header panel
    header = Text()
    header.append(meta.check_id, style="bold cyan")
    header.append(f"  v{meta.check_version}", style="dim")
    header.append("\n")
    header.append(meta.check_title, style="bold")
    console.print(Panel(header, title="Check Detail", border_style="cyan"))

    # Core fields
    console.print(f"  [bold]Severity:[/bold]     [{sev_style}]{sev}[/{sev_style}]")
    console.print(f"  [bold]Category:[/bold]     {meta.service_name}")
    console.print(f"  [bold]Resource:[/bold]     {meta.resource_type}")
    console.print()

    # Description
    if meta.description:
        console.print("  [bold]Description[/bold]")
        console.print(f"  {meta.description}")
        console.print()

    # Risk
    if meta.risk:
        console.print("  [bold]Risk[/bold]")
        console.print(f"  {meta.risk}")
        console.print()

    # Remediation
    if meta.remediation.recommendation:
        console.print("  [bold]Remediation[/bold]")
        console.print(f"  {meta.remediation.recommendation}")
        if meta.remediation.url:
            console.print(f"  [dim]Docs:[/dim] {meta.remediation.url}")
        console.print()

    # Framework mappings
    if meta.frameworks:
        table = Table(title="Framework Mappings", show_lines=False, padding=(0, 2))
        table.add_column("Framework", style="cyan", no_wrap=True)
        table.add_column("Controls")
        table.add_column("Verified", justify="center")
        for fm in meta.frameworks:
            verified = "[green]\u2713[/green]" if fm.verified else "[dim]\u2717[/dim]"
            table.add_row(fm.framework, ", ".join(fm.controls), verified)
        console.print(table)
        if any(fm.source for fm in meta.frameworks):
            console.print(f"  [dim]{meta.frameworks[0].source}[/dim]")
        console.print()

    # Technical details
    if meta.graph_api_endpoints:
        console.print("  [bold]Graph API Endpoints[/bold]")
        for ep in meta.graph_api_endpoints:
            console.print(f"    {ep}")
        console.print()

    if meta.required_permissions:
        console.print("  [bold]Required Permissions[/bold]")
        for perm in meta.required_permissions:
            console.print(f"    {perm}")
        console.print()

    if meta.required_license:
        console.print(f"  [bold]Required License:[/bold] {meta.required_license}")
        console.print()

    if meta.depends_on:
        console.print(f"  [bold]Depends On:[/bold] {', '.join(meta.depends_on)}")
        console.print()

    if meta.source_notes:
        console.print(f"  [dim]{meta.source_notes}[/dim]")
