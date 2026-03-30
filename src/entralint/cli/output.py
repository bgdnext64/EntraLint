"""Rich console output helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.console import Console
from rich.table import Table

if TYPE_CHECKING:
    from entralint.core.check import BaseCheck, Finding

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
