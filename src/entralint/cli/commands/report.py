"""entralint report — generate reports from scan results."""

from __future__ import annotations

from typing import Annotated

import typer
from rich.console import Console

console = Console()


def report(
    input_file: Annotated[
        str | None, typer.Option("--input", help="Path to scan results JSON")
    ] = None,
    format: Annotated[
        str, typer.Option("--format", help="Report format: html, pdf")
    ] = "html",
) -> None:
    """Generate a report from saved scan results."""
    console.print("[bold]EntraLint report[/bold] — not yet implemented")
    console.print(f"  Input:  {input_file or '(latest scan)'}")
    console.print(f"  Format: {format}")
    raise typer.Exit(code=0)
