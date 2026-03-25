"""entralint cache — manage the local Graph API response cache."""

from __future__ import annotations

from typing import Annotated

import typer
from rich.console import Console

console = Console()


def cache(
    clear: Annotated[
        bool, typer.Option("--clear", help="Clear the local cache")
    ] = False,
    status: Annotated[
        bool, typer.Option("--status", help="Show cache status")
    ] = False,
    tenant: Annotated[
        str | None, typer.Option(help="Scope to a specific tenant")
    ] = None,
) -> None:
    """Manage the local Graph API response cache."""
    if clear:
        console.print("[bold]Cache cleared.[/bold] (not yet implemented)")
    elif status:
        console.print("[bold]Cache status[/bold] — not yet implemented")
    else:
        console.print("[dim]Use --clear or --status.[/dim]")
    raise typer.Exit(code=0)
