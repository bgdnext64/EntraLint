"""entralint login — authenticate to an Entra ID tenant."""

from __future__ import annotations

from typing import Annotated, Any

import typer
from rich.console import Console

from entralint.auth.provider import DEFAULT_CLIENT_ID, AuthMethod, AuthProvider
from entralint.core.errors import AuthenticationError

console = Console()


def login(
    tenant: Annotated[
        str | None, typer.Option(help="Tenant ID or domain")
    ] = None,
    method: Annotated[
        str,
        typer.Option(help="Auth method: device_code (default), client_credentials"),
    ] = "device_code",
    client_id: Annotated[
        str,
        typer.Option("--client-id", help="App registration client ID"),
    ] = DEFAULT_CLIENT_ID,
) -> None:
    """Authenticate to an Entra ID tenant."""
    if not tenant:
        tenant = typer.prompt("Tenant ID or domain")

    # Try silent token first (cached/refreshed)
    auth_method = AuthMethod(method)
    provider = AuthProvider(tenant_id=tenant, client_id=client_id, method=auth_method)

    console.print("[bold]EntraLint login[/bold]")
    console.print(f"  Tenant: {tenant}")
    console.print(f"  Method: {method}")
    console.print()

    token = provider.acquire_token_silent()
    if token:
        console.print("[green]✓[/green] Authenticated using cached token.")
        raise typer.Exit(code=0)

    # No cached token — run the interactive flow
    try:
        if auth_method == AuthMethod.DEVICE_CODE:
            def _device_code_callback(flow: dict[str, Any]) -> None:
                console.print(
                    f"\n  To sign in, visit [bold cyan]{flow['verification_uri']}[/bold cyan]"
                )
                console.print(f"  and enter code [bold yellow]{flow['user_code']}[/bold yellow]\n")
                console.print("[dim]  Waiting for authentication...[/dim]")

            provider.acquire_token_device_code(callback=_device_code_callback)

        elif auth_method == AuthMethod.CLIENT_CREDENTIALS:
            provider.acquire_token_client_credentials()

        else:
            console.print(f"[red]Unsupported auth method:[/red] {method}")
            console.print("[dim]Supported: device_code, client_credentials[/dim]")
            raise typer.Exit(code=1)

    except AuthenticationError as exc:
        console.print(f"[red]Authentication failed:[/red] {exc}")
        raise typer.Exit(code=1) from None

    console.print("[green]✓[/green] Authenticated successfully. Token cached.")
    raise typer.Exit(code=0)
