"""entralint cache — manage the local Graph API response cache."""

from __future__ import annotations

from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

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
    from entralint.graph.cache import GraphCache

    gc = GraphCache()

    if clear:
        deleted = gc.clear(tenant_id=tenant)
        scope = f"tenant {tenant}" if tenant else "all tenants"
        console.print(f"[green]Cache cleared:[/green] {deleted} entries removed ({scope}).")
        gc.close()
        raise typer.Exit(code=0)

    if status:
        rows = gc.status(tenant_id=tenant)
        if not rows:
            console.print("[dim]Cache is empty.[/dim]")
            gc.close()
            raise typer.Exit(code=0)

        tbl = Table(title="Graph API Cache", show_lines=False)
        tbl.add_column("Tenant", style="cyan", no_wrap=True, max_width=12)
        tbl.add_column("Endpoint")
        tbl.add_column("Age", justify="right")
        tbl.add_column("TTL", justify="right")
        tbl.add_column("Status", justify="center")

        for r in sorted(rows, key=lambda x: (x["tenant_id"], x["endpoint"])):
            age_m = r["age_seconds"] // 60
            ttl_m = r["ttl_seconds"] // 60
            tid = r["tenant_id"]
            # Show first 8 chars of tenant ID for readability
            tid_short = tid[:8] + "…" if len(tid) > 12 else tid
            expired_label = "[red]expired[/red]" if r["expired"] else "[green]fresh[/green]"
            tbl.add_row(
                tid_short,
                r["endpoint"],
                f"{age_m}m",
                f"{ttl_m}m",
                expired_label,
            )

        console.print(tbl)
        gc.close()
        raise typer.Exit(code=0)

    console.print("[dim]Use --clear or --status.[/dim]")
    gc.close()
    raise typer.Exit(code=0)
