"""entralint scan — run security checks against an Entra ID tenant."""

from __future__ import annotations

import asyncio
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel

from entralint.auth.provider import AuthMethod, AuthProvider
from entralint.cli.output import display_scan_summary
from entralint.core.check import Finding, Status
from entralint.core.context import TenantContext
from entralint.core.engine import CheckEngine
from entralint.core.models import (
    Application,
    AppRoleAssignment,
    ConditionalAccessPolicy,
    DirectoryRoleAssignment,
    ServicePrincipal,
    User,
)
from entralint.graph.client import GraphClient
from entralint.reports.json_report import format_json
from entralint.reports.sarif_report import format_sarif

console = Console()

SEVERITY_STYLES = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "blue",
}


async def _fetch_and_scan(
    token: str,
    engine: CheckEngine,
    quiet: bool,
    verbose: bool,
) -> list[Finding]:
    """Fetch Graph data and run checks."""
    granted_permissions: set[str] = set()

    async with GraphClient(access_token=token) as graph:
        # --- Fetch Conditional Access policies ---
        if not quiet:
            console.print("  Fetching Conditional Access policies...", end=" ")
        try:
            raw_policies = await graph.get("/identity/conditionalAccess/policies")
            policies_list = raw_policies.get("value", [])
            policies = [ConditionalAccessPolicy.model_validate(p) for p in policies_list]
            granted_permissions.add("Policy.Read.All")
            if not quiet:
                console.print(f"[green]✓[/green] ({len(policies)} policies)")
        except Exception as exc:
            policies = []
            if not quiet:
                console.print(f"[red]✗[/red] ({exc})")

        # --- Fetch Applications ---
        if not quiet:
            console.print("  Fetching applications...", end=" ")
        try:
            raw_apps = await graph.get_all_pages(
                "/applications?$expand=owners($select=id,displayName)"
            )
            apps = [Application.model_validate(a) for a in raw_apps]
            granted_permissions.add("Application.Read.All")
            if not quiet:
                console.print(f"[green]✓[/green] ({len(apps)} apps)")
        except Exception as exc:
            apps = []
            if not quiet:
                console.print(f"[red]✗[/red] ({exc})")

        # --- Fetch Users (with signInActivity if P1+) ---
        if not quiet:
            console.print("  Fetching users...", end=" ")
        try:
            raw_users = await graph.get_all_pages(
                "/users?$select=id,displayName,userPrincipalName,"
                "accountEnabled,userType,createdDateTime,signInActivity"
            )
            users = [User.model_validate(u) for u in raw_users]
            granted_permissions.add("User.Read.All")
            if not quiet:
                console.print(f"[green]✓[/green] ({len(users)} users)")
        except Exception:
            # Fallback without signInActivity (requires P1 license)
            try:
                raw_users = await graph.get_all_pages("/users")
                users = [User.model_validate(u) for u in raw_users]
                granted_permissions.add("User.Read.All")
                if not quiet:
                    console.print(f"[green]✓[/green] ({len(users)} users, no sign-in data)")
            except Exception as exc:
                users = []
                if not quiet:
                    console.print(f"[red]✗[/red] ({exc})")

        # --- Fetch Security Defaults policy ---
        security_defaults: dict = {}
        if not quiet:
            console.print(
                "  Fetching security defaults policy...", end=" "
            )
        try:
            security_defaults = await graph.get(
                "/policies/identitySecurityDefaultsEnforcementPolicy"
            )
            if not quiet:
                status = "enabled" if security_defaults.get("isEnabled") else "disabled"
                console.print(f"[green]✓[/green] ({status})")
        except Exception as exc:
            if not quiet:
                console.print(f"[red]✗[/red] ({exc})")

        # --- Fetch Service Principals ---
        if not quiet:
            console.print("  Fetching service principals...", end=" ")
        try:
            raw_sps = await graph.get_all_pages("/servicePrincipals")
            service_principals = [ServicePrincipal.model_validate(sp) for sp in raw_sps]
            granted_permissions.add("Application.Read.All")
            if not quiet:
                console.print(
                    f"[green]✓[/green] ({len(service_principals)} service principals)"
                )
        except Exception as exc:
            service_principals = []
            if not quiet:
                console.print(f"[red]✗[/red] ({exc})")

        # --- Fetch Directory Role Assignments ---
        if not quiet:
            console.print("  Fetching role assignments...", end=" ")
        try:
            raw_assignments = await graph.get_all_pages(
                "/roleManagement/directory/roleAssignments"
                "?$expand=principal($select=id,displayName)"
            )
            role_assignments = [
                DirectoryRoleAssignment.model_validate(a) for a in raw_assignments
            ]
            granted_permissions.add("RoleManagement.Read.Directory")
            if not quiet:
                console.print(f"[green]✓[/green] ({len(role_assignments)} assignments)")
        except Exception as exc:
            role_assignments = []
            if not quiet:
                console.print(f"[red]✗[/red] ({exc})")

        # --- Fetch Authorization Policy ---
        authorization_policy: dict = {}
        if not quiet:
            console.print("  Fetching authorization policy...", end=" ")
        try:
            authorization_policy = await graph.get(
                "/policies/authorizationPolicy"
            )
            granted_permissions.add("Policy.Read.All")
            if not quiet:
                console.print("[green]✓[/green]")
        except Exception as exc:
            if not quiet:
                console.print(f"[red]✗[/red] ({exc})")
        # --- Fetch OAuth2 Permission Grants (delegated permissions) ---
        oauth2_grants: list[dict] = []
        if not quiet:
            console.print("  Fetching delegated permission grants...", end=" ")
        try:
            oauth2_grants = await graph.get_all_pages(
                "/oauth2PermissionGrants"
            )
            if not quiet:
                console.print(
                    f"[green]\u2713[/green] ({len(oauth2_grants)} grants)"
                )
        except Exception as exc:
            if not quiet:
                console.print(f"[red]\u2717[/red] ({exc})")

        # --- Fetch App Role Assignments (application permissions on SPs) ---
        all_app_role_assignments: list[AppRoleAssignment] = []
        if not quiet:
            console.print("  Fetching app role assignments...", end=" ")
        try:
            for sp in service_principals:
                try:
                    raw_sp_ara = await graph.get(
                        f"/servicePrincipals/{sp.id}/appRoleAssignments"
                    )
                    for item in raw_sp_ara.get("value", []):
                        all_app_role_assignments.append(
                            AppRoleAssignment.model_validate(item)
                        )
                except Exception:
                    continue
            if not quiet:
                console.print(
                    f"[green]\u2713[/green] "
                    f"({len(all_app_role_assignments)} assignments)"
                )
        except Exception as exc:
            if not quiet:
                console.print(f"[red]\u2717[/red] ({exc})")

        # --- Fetch Authentication Methods Policy ---
        auth_methods_policy: dict = {}
        if not quiet:
            console.print("  Fetching authentication methods policy...", end=" ")
        try:
            auth_methods_policy = await graph.get(
                "/policies/authenticationMethodsPolicy"
            )
            granted_permissions.add("Policy.Read.All")
            if not quiet:
                console.print("[green]\u2713[/green]")
        except Exception as exc:
            if not quiet:
                console.print(f"[red]\u2717[/red] ({exc})")

        # --- Fetch Cross-Tenant Access Default Policy ---
        cross_tenant_policy: dict = {}
        if not quiet:
            console.print("  Fetching cross-tenant access policy...", end=" ")
        try:
            cross_tenant_policy = await graph.get(
                "/policies/crossTenantAccessPolicy/default"
            )
            granted_permissions.add("Policy.Read.All")
            if not quiet:
                console.print("[green]\u2713[/green]")
        except Exception as exc:
            if not quiet:
                console.print(f"[red]\u2717[/red] ({exc})")

        # --- Fetch Named Locations ---
        named_locations: list[dict] = []
        if not quiet:
            console.print("  Fetching named locations...", end=" ")
        try:
            raw_locations = await graph.get(
                "/identity/conditionalAccess/namedLocations"
            )
            named_locations = raw_locations.get("value", [])
            granted_permissions.add("Policy.Read.All")
            if not quiet:
                console.print(
                    f"[green]\u2713[/green] ({len(named_locations)} locations)"
                )
        except Exception as exc:
            if not quiet:
                console.print(f"[red]\u2717[/red] ({exc})")

        # --- Build TenantContext ---
        context = TenantContext(
            conditional_access_policies=policies,
            applications=apps,
            users=users,
            service_principals=service_principals,
            role_assignments=role_assignments,
            app_role_assignments=all_app_role_assignments,
            oauth2_permission_grants=oauth2_grants,
            named_locations=named_locations,
            security_defaults_policy=security_defaults,
            authentication_methods_policy=auth_methods_policy,
            authorization_policy=authorization_policy,
            cross_tenant_access_policy=cross_tenant_policy,
            granted_permissions=granted_permissions,
        )

        # --- Discover and run checks ---
        checks = engine.discover()
        if not quiet:
            console.print(f"\nRunning {len(checks)} security checks...\n")

        engine.build_execution_order()
        findings = engine.execute(context)

        # --- Stream findings to console ---
        if not quiet:
            for finding in findings:
                _print_finding(finding, verbose)

        return findings


def _print_finding(finding: Finding, verbose: bool) -> None:
    """Print a single finding to the console."""
    style = SEVERITY_STYLES.get(finding.severity.value, "white")
    status_icon = {
        Status.PASS: "[green] PASS [/green]",
        Status.FAIL: f"[{style}] {finding.severity.value:8s}[/{style}]",
        Status.SKIPPED_PERMISSION: "[dim] SKIP [/dim]",
        Status.SKIPPED_LICENSE: "[dim] SKIP [/dim]",
        Status.SKIPPED_DEPENDENCY: "[dim] SKIP [/dim]",
        Status.ERROR: "[red] ERROR [/red]",
    }
    icon = status_icon.get(finding.status, "[dim] ???? [/dim]")
    console.print(f" {icon}  {finding.check_id:18s} {finding.title}")
    if verbose and finding.description:
        console.print(f"              [dim]{finding.description}[/dim]")


def scan(
    tenant: Annotated[
        str | None, typer.Option(help="Tenant ID or domain to scan")
    ] = None,
    profile: Annotated[
        str | None, typer.Option(help="Tenant profile from config")
    ] = None,
    checks: Annotated[
        str | None, typer.Option("--checks", help="Comma-separated check IDs to run")
    ] = None,
    category: Annotated[
        str | None, typer.Option(help="Filter by check category")
    ] = None,
    framework: Annotated[
        str | None, typer.Option(help="Filter by framework (CIS, CISA, NIST)")
    ] = None,
    severity: Annotated[
        str | None,
        typer.Option(help="Minimum severity filter (critical,high,medium,low)"),
    ] = None,
    output: Annotated[
        str, typer.Option(help="Output format: json, html, csv, sarif, md")
    ] = "json",
    output_file: Annotated[
        str | None, typer.Option("--output-file", help="Write report to this path")
    ] = None,
    no_cache: Annotated[
        bool, typer.Option("--no-cache", help="Bypass local data cache")
    ] = False,
    offline: Annotated[
        bool, typer.Option("--offline", help="Run checks against cached data only")
    ] = False,
    quiet: Annotated[
        bool, typer.Option("--quiet", "-q", help="Suppress console output (CI mode)")
    ] = False,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Show verbose output")
    ] = False,
) -> None:
    """Scan an Entra ID tenant for security misconfigurations."""
    # --- Resolve tenant ---
    if not tenant:
        cached = AuthProvider.list_cached_tenants()
        if len(cached) == 1:
            tenant = cached[0]
        elif len(cached) > 1:
            console.print("[yellow]Multiple cached tenants found. Specify --tenant:[/yellow]")
            for t in cached:
                console.print(f"  {t}")
            raise typer.Exit(code=1)
        else:
            console.print("[red]No cached login found. Run 'entralint login' first.[/red]")
            raise typer.Exit(code=1)

    # --- Acquire token ---
    provider = AuthProvider(tenant_id=tenant, method=AuthMethod.DEVICE_CODE)
    token = provider.acquire_token_silent()
    if not token:
        console.print(
            "[red]Token expired or missing. Run 'entralint login --tenant "
            f"{tenant}' to re-authenticate.[/red]"
        )
        raise typer.Exit(code=1)

    # --- Print banner ---
    if not quiet:
        console.print(
            Panel(
                f"Tenant: {tenant}\nProfile: {profile or 'default'}",
                title="[bold]EntraLint v0.1.0[/bold]",
                border_style="cyan",
            )
        )
        console.print("\nCollecting data from Microsoft Graph API...")

    # --- Setup engine with filters ---
    engine = CheckEngine()
    # Apply filters after discovery
    severity_list = [s.strip() for s in severity.split(",")] if severity else None
    check_ids = [c.strip() for c in checks.split(",")] if checks else None

    # --- Run scan ---
    findings = asyncio.run(
        _fetch_and_scan(
            token=token,
            engine=engine,
            quiet=quiet,
            verbose=verbose,
        )
    )

    # Apply filters if specified (post-discovery happens inside _fetch_and_scan)
    if severity_list or category or check_ids or framework:
        engine.filter_checks(
            severity=severity_list,
            category=category,
            check_ids=check_ids,
            framework=framework,
        )

    # --- Summary ---
    if not quiet:
        display_scan_summary(findings)

    # --- Output ---
    report_text: str | None = None
    if output == "json":
        report_text = format_json(findings)
    elif output == "sarif":
        # Build metadata lookup so SARIF rules get full descriptions
        meta_lookup = {
            c.metadata.check_id: c.metadata.model_dump(mode="json")
            for c in engine.discover()
        }
        report_text = format_sarif(findings, check_metadata=meta_lookup)

    if report_text is not None:
        if output_file:
            with open(output_file, "w", encoding="utf-8") as fh:
                fh.write(report_text)
            if not quiet:
                console.print(f"\n[dim]{output.upper()} report written to {output_file}[/dim]")
        elif quiet:
            # In quiet mode with no file, print to stdout for piping
            print(report_text)

    # --- Exit code ---
    has_failures = any(f.status == Status.FAIL for f in findings)
    raise typer.Exit(code=1 if has_failures else 0)


def scan_all(
    profile: Annotated[
        str | None, typer.Option(help="Multi-tenant profile from config")
    ] = None,
) -> None:
    """Scan all configured tenants."""
    console.print("[bold]EntraLint scan-all[/bold] — not yet implemented")
    console.print(f"  Profile: {profile or 'all'}")
    raise typer.Exit(code=0)
