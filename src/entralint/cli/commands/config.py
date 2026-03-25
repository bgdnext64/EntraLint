"""entralint config — manage tenant configuration."""

from __future__ import annotations

from typing import Annotated

import typer
from rich.console import Console

console = Console()


def config(
    init: Annotated[
        bool, typer.Option("--init", help="Create a new config file")
    ] = False,
    add_tenant: Annotated[
        bool, typer.Option("--add-tenant", help="Add a new tenant interactively")
    ] = False,
    list_tenants: Annotated[
        bool, typer.Option("--list-tenants", help="List configured tenants")
    ] = False,
) -> None:
    """Manage EntraLint configuration."""
    if init:
        console.print("[bold]EntraLint config --init[/bold] — not yet implemented")
    elif add_tenant:
        console.print("[bold]EntraLint config --add-tenant[/bold] — not yet implemented")
    elif list_tenants:
        console.print("[bold]EntraLint config --list-tenants[/bold] — not yet implemented")
    else:
        console.print("[dim]Use --init, --add-tenant, or --list-tenants.[/dim]")
    raise typer.Exit(code=0)
