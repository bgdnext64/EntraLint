# ruff: noqa: E501
"""Generate scripts to grant required Microsoft Graph API permissions."""

from __future__ import annotations

from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

# Well-known Microsoft Graph service principal appId (same across all tenants)
MS_GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"

# Map permission names to their well-known Microsoft Graph app role IDs
# These GUIDs are stable across all Entra ID tenants.
PERMISSION_ROLE_IDS: dict[str, str] = {
    "Directory.Read.All": "7ab1d382-f21e-4acd-a863-ba3e13f7da61",
    "Policy.Read.All": "246dd0d5-5bd0-4def-940b-0421030a5b68",
    "Application.Read.All": "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30",
    "RoleManagement.Read.Directory": "483bed4a-2ad3-4361-a73b-c83ccdbdc53c",
    "User.Read.All": "df021288-bdef-4463-88db-98f22de89214",
    "AuditLog.Read.All": "b0afded3-3588-46d8-8b3d-9842eff778da",
    "AgentIdentity.Read.All": "a30a7ae2-ca2e-48a0-b920-be0fda7b0381",
    "DelegatedPermissionGrant.Read.All": "89c8469c-83ad-45f7-8ff2-6e3d4285709e",
    "DelegatedPermissionGrant.ReadWrite.All": "8e8e4742-1d95-4f68-9d56-6ee75648c72a",
}


def permissions(
    format: Annotated[
        str,
        typer.Option(
            "--format", "-f",
            help="Script format: powershell, azcli, or table",
        ),
    ] = "table",
    client_id: Annotated[
        str | None,
        typer.Option(
            "--client-id",
            help="App registration client ID to grant permissions to",
        ),
    ] = None,
) -> None:
    """Show required permissions and generate grant scripts.

    Lists every Microsoft Graph API permission needed by EntraLint checks
    and generates a ready-to-run script to grant them.
    """
    from pathlib import Path

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

    # Aggregate: permission -> list of check IDs that need it
    perm_to_checks: dict[str, list[str]] = {}
    for check in checks:
        for perm in check.metadata.required_permissions:
            perm_to_checks.setdefault(perm, []).append(
                check.metadata.check_id
            )

    all_perms = sorted(perm_to_checks.keys())

    fmt = format.lower()
    if fmt == "table":
        _print_table(all_perms, perm_to_checks)
    elif fmt in ("powershell", "ps", "ps1"):
        _print_powershell(all_perms, perm_to_checks, client_id)
    elif fmt in ("azcli", "az", "cli"):
        _print_azcli(all_perms, perm_to_checks, client_id)
    else:
        console.print(
            f"[red]Unknown format:[/red] {format}. "
            "Use: table, powershell, or azcli"
        )
        raise typer.Exit(code=1)


def _print_table(
    all_perms: list[str],
    perm_to_checks: dict[str, list[str]],
) -> None:
    """Display permissions as a Rich table."""
    table = Table(title="EntraLint Required Permissions", show_lines=True)
    table.add_column("Permission", style="bold cyan", min_width=30)
    table.add_column("Checks", justify="right", style="dim")
    table.add_column("Known Role ID", style="dim", min_width=36)

    for perm in all_perms:
        count = len(perm_to_checks[perm])
        role_id = PERMISSION_ROLE_IDS.get(perm, "—")
        table.add_row(perm, f"{count} checks", role_id)

    console.print(table)
    console.print()
    console.print(
        "[dim]Generate a grant script with:[/dim]  "
        "[bold]entralint permissions -f powershell --client-id YOUR_APP_ID[/bold]"
    )
    console.print(
        "[dim]                          or:[/dim]  "
        "[bold]entralint permissions -f azcli --client-id YOUR_APP_ID[/bold]"
    )


def _print_powershell(
    all_perms: list[str],
    perm_to_checks: dict[str, list[str]],
    client_id: str | None,
) -> None:
    """Generate a PowerShell script using Microsoft Graph PowerShell SDK."""
    app_id_val = client_id or "<YOUR_APP_CLIENT_ID>"

    lines = [
        "# ---------------------------------------------------------------",
        "# EntraLint — Grant Required Microsoft Graph Permissions",
        "# ---------------------------------------------------------------",
        "# This script grants application permissions to the EntraLint app",
        "# registration so all 88 checks can run without skipping.",
        "#",
        "# Prerequisites:",
        "#   Install-Module Microsoft.Graph -Scope CurrentUser",
        "#",
        "# Run as a Global Administrator or Privileged Role Administrator.",
        "# ---------------------------------------------------------------",
        "",
        "# Connect with the required admin scopes",
        'Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All","Application.Read.All" -NoWelcome',
        "",
        f'$clientId = "{app_id_val}"',
        "",
        "# Look up the EntraLint service principal in your tenant",
        '$sp = Get-MgServicePrincipal -Filter "appId eq \'$clientId\'"',
        "if (-not $sp) {",
        '    Write-Error "Service principal not found for appId $clientId. Register the app first."',
        "    exit 1",
        "}",
        "",
        "# Microsoft Graph service principal (same in every tenant)",
        f'$graphSp = Get-MgServicePrincipal -Filter "appId eq \'{MS_GRAPH_APP_ID}\'"',
        "",
        "# Permissions to grant",
        "$permissions = @(",
    ]

    for perm in all_perms:
        role_id = PERMISSION_ROLE_IDS.get(perm)
        count = len(perm_to_checks[perm])
        if role_id:
            lines.append(
                f'    @{{ Name = "{perm}"; '
                f'RoleId = "{role_id}" '
                f"}}  # {count} checks"
            )
        else:
            lines.append(
                f'    # "{perm}" — role ID not in built-in map, '
                f"look up manually ({count} checks)"
            )

    lines += [
        ")",
        "",
        "# Grant each permission",
        "foreach ($p in $permissions) {",
        "    $existing = Get-MgServicePrincipalAppRoleAssignment "
        "-ServicePrincipalId $sp.Id |",
        '        Where-Object { $_.AppRoleId -eq $p.RoleId }',
        "    if ($existing) {",
        '        Write-Host "  Already granted: $($p.Name)" '
        "-ForegroundColor DarkGray",
        "    } else {",
        "        New-MgServicePrincipalAppRoleAssignment `",
        "            -ServicePrincipalId $sp.Id `",
        "            -PrincipalId $sp.Id `",
        "            -ResourceId $graphSp.Id `",
        "            -AppRoleId $p.RoleId | Out-Null",
        '        Write-Host "  Granted: $($p.Name)" -ForegroundColor Green',
        "    }",
        "}",
        "",
        'Write-Host ""',
        'Write-Host "Done. All EntraLint permissions granted." '
        "-ForegroundColor Cyan",
        'Write-Host "You can now run: entralint scan"',
    ]

    script = "\n".join(lines)

    if client_id:
        console.print(
            Panel(
                script,
                title="PowerShell — Grant Permissions",
                subtitle="Copy and run in an admin PowerShell session",
                border_style="cyan",
            )
        )
    else:
        console.print(
            "[yellow]Tip:[/yellow] Pass [bold]--client-id[/bold] "
            "to fill in the app ID automatically.\n"
        )
        console.print(
            Panel(
                script,
                title="PowerShell — Grant Permissions",
                subtitle="Replace <YOUR_APP_CLIENT_ID> with your app registration ID",
                border_style="cyan",
            )
        )


def _print_azcli(
    all_perms: list[str],
    perm_to_checks: dict[str, list[str]],
    client_id: str | None,
) -> None:
    """Generate an Azure CLI script."""
    app_id_val = client_id or "<YOUR_APP_CLIENT_ID>"

    lines = [
        "#!/bin/bash",
        "# ---------------------------------------------------------------",
        "# EntraLint — Grant Required Microsoft Graph Permissions",
        "# ---------------------------------------------------------------",
        "# This script grants application permissions to the EntraLint app",
        "# registration so all 88 checks can run without skipping.",
        "#",
        "# Prerequisites: Azure CLI (az) logged in as Global Admin",
        "# ---------------------------------------------------------------",
        "",
        f'CLIENT_ID="{app_id_val}"',
        f'GRAPH_APP_ID="{MS_GRAPH_APP_ID}"',
        "",
        "# Get the service principal object ID for the EntraLint app",
        'SP_ID=$(az ad sp list --filter "appId eq \'$CLIENT_ID\'" '
        "--query '[0].id' -o tsv)",
        'if [ -z "$SP_ID" ]; then',
        '    echo "Error: Service principal not found for $CLIENT_ID"',
        "    exit 1",
        "fi",
        "",
        "# Get the Microsoft Graph service principal object ID",
        'GRAPH_SP_ID=$(az ad sp list --filter "appId eq \'$GRAPH_APP_ID\'" '
        "--query '[0].id' -o tsv)",
        "",
        "echo \"Granting permissions to service principal $SP_ID...\"",
        "",
    ]

    for perm in all_perms:
        role_id = PERMISSION_ROLE_IDS.get(perm)
        count = len(perm_to_checks[perm])
        if role_id:
            lines += [
                f"# {perm} ({count} checks)",
                "az rest --method POST \\",
                "  --uri \"https://graph.microsoft.com/v1.0/servicePrincipals/$SP_ID/appRoleAssignments\" \\",
                f"  --body '{{\"principalId\": \"'$SP_ID'\", \"resourceId\": \"'$GRAPH_SP_ID'\", \"appRoleId\": \"{role_id}\"}}' \\",
                f"  2>/dev/null && echo \"  Granted: {perm}\" || echo \"  Already granted or failed: {perm}\"",
                "",
            ]
        else:
            lines.append(
                f"# {perm} — role ID not in built-in map, "
                f"look up manually ({count} checks)"
            )

    lines += [
        'echo ""',
        'echo "Done. All EntraLint permissions granted."',
        'echo "You can now run: entralint scan"',
    ]

    script = "\n".join(lines)

    if client_id:
        console.print(
            Panel(
                script,
                title="Azure CLI — Grant Permissions",
                subtitle="Copy and run in a bash terminal",
                border_style="cyan",
            )
        )
    else:
        console.print(
            "[yellow]Tip:[/yellow] Pass [bold]--client-id[/bold] "
            "to fill in the app ID automatically.\n"
        )
        console.print(
            Panel(
                script,
                title="Azure CLI — Grant Permissions",
                subtitle="Replace <YOUR_APP_CLIENT_ID> with your app registration ID",
                border_style="cyan",
            )
        )
