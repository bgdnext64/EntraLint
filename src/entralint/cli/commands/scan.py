"""entralint scan — run security checks against an Entra ID tenant."""

from __future__ import annotations

import asyncio
import contextlib
from contextlib import contextmanager
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from entralint.auth.provider import AuthMethod, AuthProvider
from entralint.cli.output import display_scan_summary
from entralint.core.check import SEVERITY_RANK, Finding, Severity, Status
from entralint.core.config import load_config_auto
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
from entralint.reports.html_report import format_html
from entralint.reports.json_report import format_json
from entralint.reports.sarif_report import format_sarif

console = Console()


@contextmanager
def _nullcontext():
    """No-op context manager for when status spinner is suppressed."""
    yield


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
) -> list[Finding]:
    """Fetch Graph data and run checks."""
    granted_permissions: set[str] = set()
    fetch_results: list[tuple[str, str, str]] = []  # (label, status_icon, detail)

    def _ok(label: str, detail: str = "") -> None:
        fetch_results.append((label, "[green]OK[/green]", detail))

    def _fail(label: str, detail: str = "") -> None:
        fetch_results.append((label, "[red]FAIL[/red]", detail))

    async with GraphClient(access_token=token) as graph:
        with console.status(
            "[bold cyan]Collecting data from Microsoft Graph API...",
            spinner="dots",
        ) if not quiet else _nullcontext():

            # --- Conditional Access policies ---
            try:
                raw_policies = await graph.get(
                    "/identity/conditionalAccess/policies"
                )
                policies_list = raw_policies.get("value", [])
                policies = [
                    ConditionalAccessPolicy.model_validate(p) for p in policies_list
                ]
                granted_permissions.add("Policy.Read.All")
                _ok("Conditional Access policies", f"{len(policies)} policies")
            except Exception as exc:
                policies = []
                _fail("Conditional Access policies", str(exc))

            # --- Applications ---
            try:
                raw_apps = await graph.get_all_pages(
                    "/applications?$expand=owners($select=id,displayName)"
                )
                apps = [Application.model_validate(a) for a in raw_apps]
                granted_permissions.add("Application.Read.All")
                _ok("Applications", f"{len(apps)} apps")
            except Exception as exc:
                apps = []
                _fail("Applications", str(exc))

            # --- Users (with signInActivity if P1+) ---
            try:
                raw_users = await graph.get_all_pages(
                    "/users?$select=id,displayName,userPrincipalName,"
                    "accountEnabled,userType,createdDateTime,signInActivity"
                )
                users = [User.model_validate(u) for u in raw_users]
                granted_permissions.add("User.Read.All")
                _ok("Users", f"{len(users)} users")
            except Exception:
                try:
                    raw_users = await graph.get_all_pages("/users")
                    users = [User.model_validate(u) for u in raw_users]
                    granted_permissions.add("User.Read.All")
                    _ok("Users", f"{len(users)} users, no sign-in data")
                except Exception as exc:
                    users = []
                    _fail("Users", str(exc))

            # --- Security Defaults policy ---
            security_defaults: dict = {}
            try:
                security_defaults = await graph.get(
                    "/policies/identitySecurityDefaultsEnforcementPolicy"
                )
                status = "enabled" if security_defaults.get("isEnabled") else "disabled"
                _ok("Security defaults", status)
            except Exception as exc:
                _fail("Security defaults", str(exc))

            # --- Service Principals ---
            try:
                raw_sps = await graph.get_all_pages("/servicePrincipals")
                service_principals = [
                    ServicePrincipal.model_validate(sp) for sp in raw_sps
                ]
                granted_permissions.add("Application.Read.All")
                _ok("Service principals", f"{len(service_principals)} SPs")
            except Exception as exc:
                service_principals = []
                _fail("Service principals", str(exc))

            # --- Directory Role Assignments ---
            try:
                raw_assignments = await graph.get_all_pages(
                    "/roleManagement/directory/roleAssignments"
                    "?$expand=principal($select=id,displayName)"
                )
                role_assignments = [
                    DirectoryRoleAssignment.model_validate(a)
                    for a in raw_assignments
                ]
                granted_permissions.add("RoleManagement.Read.Directory")
                _ok("Role assignments", f"{len(role_assignments)} assignments")
            except Exception as exc:
                role_assignments = []
                _fail("Role assignments", str(exc))

            # --- Authorization Policy ---
            authorization_policy: dict = {}
            try:
                authorization_policy = await graph.get(
                    "/policies/authorizationPolicy"
                )
                granted_permissions.add("Policy.Read.All")
                _ok("Authorization policy")
            except Exception as exc:
                _fail("Authorization policy", str(exc))

            # --- OAuth2 Permission Grants ---
            oauth2_grants: list[dict] = []
            try:
                oauth2_grants = await graph.get_all_pages(
                    "/oauth2PermissionGrants"
                )
                _ok("Delegated permission grants", f"{len(oauth2_grants)} grants")
            except Exception as exc:
                _fail("Delegated permission grants", str(exc))

            # --- App Role Assignments ---
            all_app_role_assignments: list[AppRoleAssignment] = []
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
                _ok(
                    "App role assignments",
                    f"{len(all_app_role_assignments)} assignments",
                )
            except Exception as exc:
                _fail("App role assignments", str(exc))

            # --- Authentication Methods Policy ---
            auth_methods_policy: dict = {}
            try:
                auth_methods_policy = await graph.get(
                    "/policies/authenticationMethodsPolicy"
                )
                granted_permissions.add("Policy.Read.All")
                _ok("Authentication methods policy")
            except Exception as exc:
                _fail("Authentication methods policy", str(exc))

            # --- Cross-Tenant Access Default Policy ---
            cross_tenant_policy: dict = {}
            try:
                cross_tenant_policy = await graph.get(
                    "/policies/crossTenantAccessPolicy/default"
                )
                granted_permissions.add("Policy.Read.All")
                _ok("Cross-tenant access policy")
            except Exception as exc:
                _fail("Cross-tenant access policy", str(exc))

            # --- Named Locations ---
            named_locations: list[dict] = []
            try:
                raw_locations = await graph.get(
                    "/identity/conditionalAccess/namedLocations"
                )
                named_locations = raw_locations.get("value", [])
                granted_permissions.add("Policy.Read.All")
                _ok("Named locations", f"{len(named_locations)} locations")
            except Exception as exc:
                _fail("Named locations", str(exc))

        # --- Display fetch results as a compact table ---
        if not quiet:
            tbl = Table(
                show_header=False, box=None, padding=(0, 1),
                show_edge=False,
            )
            tbl.add_column(width=4)  # status icon
            tbl.add_column(min_width=32)  # label
            tbl.add_column(style="dim")  # detail
            for label, icon, detail in fetch_results:
                tbl.add_row(icon, label, detail)
            console.print(tbl)

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
    fmt: Annotated[
        str,
        typer.Option(
            "--format", "-f",
            help="Output format: table (default), json, sarif, html",
        ),
    ] = "table",
    output_file: Annotated[
        str | None, typer.Option("--output-file", help="Write report to this path")
    ] = None,
    no_cache: Annotated[
        bool, typer.Option("--no-cache", help="Bypass local data cache")
    ] = False,
    offline: Annotated[
        bool, typer.Option("--offline", help="Run checks against cached data only")
    ] = False,
    fail_on: Annotated[
        str | None,
        typer.Option(
            "--fail-on",
            help="Severity threshold for non-zero exit (default: medium)",
        ),
    ] = None,
    config: Annotated[
        str | None,
        typer.Option("--config", help="Path to .entralint.yaml config file"),
    ] = None,
    no_config: Annotated[
        bool,
        typer.Option("--no-config", help="Ignore config file"),
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

    # For structured output formats piped to stdout, suppress Rich console output.
    # When writing to a file, show table output alongside.
    fmt_lower = fmt.lower()
    suppress_console = quiet or (fmt_lower != "table" and not output_file)

    # --- Load config ---
    cfg = load_config_auto(config, disabled=no_config)
    effective_fail_on = fail_on or (cfg.fail_on if cfg else None) or "medium"

    # --- Print banner ---
    if not suppress_console:
        console.print(
            Panel(
                f"Tenant: {tenant}\nProfile: {profile or 'default'}",
                title="[bold]EntraLint v0.1.0[/bold]",
                border_style="cyan",
                safe_box=True,
            )
        )
        console.print()

    # --- Setup engine with filters ---
    engine = CheckEngine()
    # Apply filters after discovery
    severity_list = [s.strip() for s in severity.split(",")] if severity else None
    check_ids = [c.strip() for c in checks.split(",")] if checks else None

    # Merge config-level exclusions into check_ids filter
    exclude_set: set[str] = set()
    if cfg:
        exclude_set.update(cfg.exclude_checks)
        exclude_set.update(r.check for r in cfg.suppress)

    # --- Run scan ---
    findings = asyncio.run(
        _fetch_and_scan(
            token=token,
            engine=engine,
            quiet=suppress_console,
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

    # --- Apply config: suppressions + severity overrides ---
    if cfg:
        # Remove suppressed findings
        if exclude_set:
            findings = [
                f for f in findings if f.check_id not in exclude_set
            ]
        # Apply severity overrides
        for f in findings:
            override = cfg.overrides.get(f.check_id)
            if override:
                with contextlib.suppress(ValueError):
                    f.severity = Severity(override.severity.upper())

    # --- Stream findings to console ---
    if not suppress_console:
        for finding in findings:
            _print_finding(finding, verbose)

    # --- Summary ---
    if not suppress_console:
        display_scan_summary(findings)

    # --- Output ---
    if fmt_lower not in ("table", "json", "sarif", "html"):
        console.print(f"[red]Unknown format '{fmt}'. Use: table, json, sarif, html[/red]")
        raise typer.Exit(code=2)

    report_text: str | None = None
    if fmt_lower == "json":
        report_text = format_json(findings)
    elif fmt_lower == "sarif":
        meta_lookup = {
            c.metadata.check_id: c.metadata.model_dump(mode="json")
            for c in engine.discover()
        }
        report_text = format_sarif(findings, check_metadata=meta_lookup)
    elif fmt_lower == "html":
        meta_lookup = {
            c.metadata.check_id: c.metadata.model_dump(mode="json")
            for c in engine.discover()
        }
        report_text = format_html(
            findings, tenant_id=tenant, check_metadata=meta_lookup,
        )
        # Default to file output for HTML
        if not output_file:
            output_file = "entralint-report.html"

    if report_text is not None:
        if output_file:
            with open(output_file, "w", encoding="utf-8") as fh:
                fh.write(report_text)
            console.print(
                f"\n[dim]{fmt_lower.upper()} report written to {output_file}[/dim]"
            )
        else:
            print(report_text)

    # --- Exit code ---
    fail_on_lower = effective_fail_on.lower()
    if fail_on_lower == "none":
        raise typer.Exit(code=0)

    threshold_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
    }
    threshold = threshold_map.get(fail_on_lower)
    if threshold is None:
        console.print(
            f"[red]Unknown --fail-on value '{fail_on}'. "
            "Use: critical, high, medium, low, none[/red]"
        )
        raise typer.Exit(code=2)

    threshold_rank = SEVERITY_RANK[threshold]
    has_failures = any(
        f.status == Status.FAIL and SEVERITY_RANK.get(f.severity, 99) <= threshold_rank
        for f in findings
    )
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
