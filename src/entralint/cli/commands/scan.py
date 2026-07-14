"""entralint scan — run security checks against an Entra ID tenant."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated

import httpx
import typer
from pydantic import ValidationError
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from entralint.auth.provider import AuthMethod, AuthProvider
from entralint.cli.output import display_baseline_delta, display_scan_summary
from entralint.core.baseline import (
    DEFAULT_BASELINE_FILE,
    compare,
    load_baseline,
    save_baseline,
)
from entralint.core.check import SEVERITY_RANK, Finding, Severity, Status
from entralint.core.config import load_config_auto
from entralint.core.context import TenantContext
from entralint.core.engine import CheckEngine
from entralint.core.errors import AuthenticationError, GraphAPIError
from entralint.core.models import (
    AgentIdentity,
    AgentIdentityBlueprint,
    AgentIdentityBlueprintPrincipal,
    Application,
    AppRoleAssignment,
    ConditionalAccessPolicy,
    DirectoryRoleAssignment,
    InheritablePermission,
    ServicePrincipal,
    User,
)
from entralint.graph.client import GraphClient
from entralint.reports.html_report import format_html
from entralint.reports.json_report import format_json
from entralint.reports.sarif_report import format_sarif

logger = logging.getLogger(__name__)
console = Console()

# Exception types we expect during fetch-and-degrade. Anything else
# (e.g. AuthenticationExpiredError, programming errors) is fatal and must
# propagate to the caller rather than silently producing empty data.
_EXPECTED_FETCH_ERRORS: tuple[type[BaseException], ...] = (
    GraphAPIError,
    ValidationError,
    httpx.HTTPError,
)


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


# Bound concurrent Graph fan-out to avoid tripping throttling.
_SP_FANOUT_CONCURRENCY = 10


async def _fetch_with_select_fallback(
    graph: GraphClient,
    endpoint_with_select: str,
    fallback_endpoint: str,
) -> list[dict]:
    """Try a ``$select``-ed endpoint first, fall back to the plain endpoint.

    Some Graph endpoints (notably ``/users?$select=signInActivity``) require
    an Entra ID P1 license. On licensing failures we transparently retry
    without the projection so scans still surface something useful.
    """
    try:
        return await graph.get_all_pages(endpoint_with_select)
    except _EXPECTED_FETCH_ERRORS as exc:
        logger.debug(
            "Falling back from %s to %s: %s",
            endpoint_with_select,
            fallback_endpoint,
            exc,
        )
        return await graph.get_all_pages(fallback_endpoint)


async def _fetch_sp_app_role_assignments(
    graph: GraphClient,
    service_principals: list[ServicePrincipal],
) -> list[AppRoleAssignment]:
    """Fetch ``appRoleAssignments`` for every service principal concurrently.

    Uses a :class:`~asyncio.Semaphore` to cap concurrency at
    ``_SP_FANOUT_CONCURRENCY`` so we don't trigger Graph throttling.
    Per-SP failures are logged and skipped so one bad SP can't blank out
    the entire result set.
    """
    if not service_principals:
        return []

    sem = asyncio.Semaphore(_SP_FANOUT_CONCURRENCY)

    async def _one(sp: ServicePrincipal) -> list[AppRoleAssignment]:
        async with sem:
            try:
                raw = await graph.get(
                    f"/servicePrincipals/{sp.id}/appRoleAssignments"
                )
            except _EXPECTED_FETCH_ERRORS as exc:
                logger.debug(
                    "appRoleAssignments fetch failed for sp=%s",
                    sp.id,
                    exc_info=exc,
                )
                return []
            return [
                AppRoleAssignment.model_validate(item)
                for item in raw.get("value", [])
            ]

    results = await asyncio.gather(*(_one(sp) for sp in service_principals))
    return [ara for sublist in results for ara in sublist]


async def _fetch_and_scan(
    token: str,
    engine: CheckEngine,
    quiet: bool,
    *,
    tenant_id: str | None = None,
    no_cache: bool = False,
    offline: bool = False,
) -> tuple[list[Finding], str, str]:
    """Fetch Graph data and run checks.

    Returns (findings, tenant_display_name, tenant_primary_domain).
    """
    """Fetch Graph data and run checks."""
    granted_permissions: set[str] = set()
    fetch_results: list[tuple[str, str, str]] = []  # (label, status_icon, detail)

    def _ok(label: str, detail: str = "") -> None:
        fetch_results.append((label, "[green]OK[/green]", detail))

    def _fail(label: str, detail: str = "") -> None:
        fetch_results.append((label, "[red]FAIL[/red]", detail))

    async with GraphClient(
        access_token=token,
        tenant_id=tenant_id,
        no_cache=no_cache,
        offline=offline,
    ) as graph:
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
            except _EXPECTED_FETCH_ERRORS as exc:
                policies = []
                logger.debug("Conditional Access fetch failed", exc_info=exc)
                _fail("Conditional Access policies", str(exc))

            # --- Applications ---
            try:
                raw_apps = await graph.get_all_pages(
                    "/applications?$expand=owners($select=id,displayName)"
                )
                apps = [Application.model_validate(a) for a in raw_apps]
                granted_permissions.add("Application.Read.All")
                _ok("Applications", f"{len(apps)} apps")
            except _EXPECTED_FETCH_ERRORS as exc:
                apps = []
                logger.debug("Applications fetch failed", exc_info=exc)
                _fail("Applications", str(exc))

            # --- Users (with signInActivity if P1+) ---
            # P1 licensing is required for signInActivity; if that fails we
            # transparently fall back to a plain /users listing so checks
            # that don't need sign-in data still run.
            try:
                raw_users = await _fetch_with_select_fallback(
                    graph,
                    "/users?$select=id,displayName,userPrincipalName,"
                    "accountEnabled,userType,createdDateTime,signInActivity",
                    "/users",
                )
                users = [User.model_validate(u) for u in raw_users]
                granted_permissions.add("User.Read.All")
                _ok("Users", f"{len(users)} users")
            except _EXPECTED_FETCH_ERRORS as exc:
                users = []
                logger.debug("Users fetch failed", exc_info=exc)
                _fail("Users", str(exc))

            # --- Organization ---
            org_display_name = ""
            org_primary_domain = ""
            try:
                raw_org = await graph.get("/organization")
                org_list = raw_org.get("value", [])
                if org_list:
                    org = org_list[0]
                    org_display_name = org.get("displayName", "")
                    # Get primary verified domain
                    domains = org.get("verifiedDomains", [])
                    org_primary_domain = next(
                        (d["name"] for d in domains if d.get("isDefault")),
                        "",
                    )
                    detail = org_display_name
                    if org_primary_domain:
                        detail += f" ({org_primary_domain})"
                    _ok("Organization", detail)
            except _EXPECTED_FETCH_ERRORS as exc:
                logger.debug("Organization fetch failed", exc_info=exc)
                _fail("Organization", str(exc))

            # --- Security Defaults policy ---
            security_defaults: dict = {}
            try:
                security_defaults = await graph.get(
                    "/policies/identitySecurityDefaultsEnforcementPolicy"
                )
                status = "enabled" if security_defaults.get("isEnabled") else "disabled"
                _ok("Security defaults", status)
            except _EXPECTED_FETCH_ERRORS as exc:
                logger.debug("Security defaults fetch failed", exc_info=exc)
                _fail("Security defaults", str(exc))

            # --- Service Principals ---
            try:
                raw_sps = await graph.get_all_pages("/servicePrincipals")
                service_principals = [
                    ServicePrincipal.model_validate(sp) for sp in raw_sps
                ]
                granted_permissions.add("Application.Read.All")
                _ok("Service principals", f"{len(service_principals)} SPs")
            except _EXPECTED_FETCH_ERRORS as exc:
                service_principals = []
                logger.debug("Service principals fetch failed", exc_info=exc)
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
            except _EXPECTED_FETCH_ERRORS as exc:
                role_assignments = []
                logger.debug("Role assignments fetch failed", exc_info=exc)
                _fail("Role assignments", str(exc))

            # --- Authorization Policy ---
            authorization_policy: dict = {}
            try:
                authorization_policy = await graph.get(
                    "/policies/authorizationPolicy"
                )
                granted_permissions.add("Policy.Read.All")
                _ok("Authorization policy")
            except _EXPECTED_FETCH_ERRORS as exc:
                logger.debug("Authorization policy fetch failed", exc_info=exc)
                _fail("Authorization policy", str(exc))

            # --- OAuth2 Permission Grants ---
            oauth2_grants: list[dict] = []
            try:
                oauth2_grants = await graph.get_all_pages(
                    "/oauth2PermissionGrants"
                )
                _ok("Delegated permission grants", f"{len(oauth2_grants)} grants")
            except _EXPECTED_FETCH_ERRORS as exc:
                logger.debug("OAuth2 grants fetch failed", exc_info=exc)
                _fail("Delegated permission grants", str(exc))

            # --- App Role Assignments ---
            # Fetched concurrently (bounded) — one request per service
            # principal is O(N); a sequential loop dominated scan time on
            # tenants with thousands of SPs.
            all_app_role_assignments: list[AppRoleAssignment] = []
            try:
                all_app_role_assignments = await _fetch_sp_app_role_assignments(
                    graph, service_principals
                )
                _ok(
                    "App role assignments",
                    f"{len(all_app_role_assignments)} assignments",
                )
            except _EXPECTED_FETCH_ERRORS as exc:
                logger.debug("App role assignments outer fetch failed", exc_info=exc)
                _fail("App role assignments", str(exc))

            # --- Authentication Methods Policy ---
            auth_methods_policy: dict = {}
            try:
                auth_methods_policy = await graph.get(
                    "/policies/authenticationMethodsPolicy"
                )
                granted_permissions.add("Policy.Read.All")
                _ok("Authentication methods policy")
            except _EXPECTED_FETCH_ERRORS as exc:
                logger.debug("Authentication methods policy fetch failed", exc_info=exc)
                _fail("Authentication methods policy", str(exc))

            # --- Cross-Tenant Access Default Policy ---
            cross_tenant_policy: dict = {}
            try:
                cross_tenant_policy = await graph.get(
                    "/policies/crossTenantAccessPolicy/default"
                )
                granted_permissions.add("Policy.Read.All")
                _ok("Cross-tenant access policy")
            except _EXPECTED_FETCH_ERRORS as exc:
                logger.debug("Cross-tenant policy fetch failed", exc_info=exc)
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
            except _EXPECTED_FETCH_ERRORS as exc:
                logger.debug("Named locations fetch failed", exc_info=exc)
                _fail("Named locations", str(exc))

            # --- Agent Identity Blueprints ---
            agent_blueprints: list[AgentIdentityBlueprint] = []
            try:
                raw_bps = await graph.get_all_pages(
                    "/applications/microsoft.graph.agentIdentityBlueprint"
                )
                for bp_raw in raw_bps:
                    bp = AgentIdentityBlueprint.model_validate(bp_raw)
                    # Fetch owners, sponsors, inheritable permissions
                    with contextlib.suppress(Exception):
                        owners_resp = await graph.get(
                            f"/applications/{bp.id}/owners"
                        )
                        bp.owners = owners_resp.get("value", [])
                    with contextlib.suppress(Exception):
                        sponsors_resp = await graph.get(
                            f"/applications/{bp.id}/sponsors"
                        )
                        bp.sponsors = sponsors_resp.get("value", [])
                    with contextlib.suppress(Exception):
                        ip_resp = await graph.get(
                            f"/applications/{bp.id}"
                            "/inheritablePermissions"
                        )
                        bp.inheritable_permissions = [
                            InheritablePermission.model_validate(ip)
                            for ip in ip_resp.get("value", [])
                        ]
                    with contextlib.suppress(Exception):
                        fic_resp = await graph.get(
                            f"/applications/{bp.id}"
                            "/federatedIdentityCredentials"
                        )
                        bp.federated_identity_credentials = (
                            fic_resp.get("value", [])
                        )
                    agent_blueprints.append(bp)
                granted_permissions.add("AgentIdentity.Read.All")
                _ok(
                    "Agent identity blueprints",
                    f"{len(agent_blueprints)} blueprints",
                )
            except _EXPECTED_FETCH_ERRORS as exc:
                logger.debug("Agent blueprints fetch failed", exc_info=exc)
                _fail("Agent identity blueprints", str(exc))

            # --- Agent Identity Blueprint Principals ---
            agent_bp_principals: list[AgentIdentityBlueprintPrincipal] = []
            try:
                raw_bpps = await graph.get_all_pages(
                    "/servicePrincipals/microsoft.graph"
                    ".agentIdentityBlueprintPrincipal"
                )
                for bpp_raw in raw_bpps:
                    bpp = AgentIdentityBlueprintPrincipal.model_validate(
                        bpp_raw
                    )
                    with contextlib.suppress(Exception):
                        owners_resp = await graph.get(
                            f"/servicePrincipals/{bpp.id}/owners"
                        )
                        bpp.owners = owners_resp.get("value", [])
                    with contextlib.suppress(Exception):
                        sponsors_resp = await graph.get(
                            f"/servicePrincipals/{bpp.id}/sponsors"
                        )
                        bpp.sponsors = sponsors_resp.get("value", [])
                    agent_bp_principals.append(bpp)
                _ok(
                    "Agent blueprint principals",
                    f"{len(agent_bp_principals)} principals",
                )
            except _EXPECTED_FETCH_ERRORS as exc:
                logger.debug("Agent blueprint principals fetch failed", exc_info=exc)
                _fail("Agent blueprint principals", str(exc))

            # --- Agent Identities ---
            agent_identities: list[AgentIdentity] = []
            try:
                raw_agents = await _fetch_with_select_fallback(
                    graph,
                    "/servicePrincipals/microsoft.graph"
                    ".agentIdentity?$select=id,displayName,appId,"
                    "agentIdentityBlueprintId,accountEnabled,"
                    "servicePrincipalType,createdByAppId,createdDateTime,"
                    "disabledByMicrosoftStatus,tags,signInActivity",
                    "/servicePrincipals/microsoft.graph"
                    ".agentIdentity",
                )
                for ag_raw in raw_agents:
                    ag = AgentIdentity.model_validate(ag_raw)
                    with contextlib.suppress(Exception):
                        owners_resp = await graph.get(
                            f"/servicePrincipals/{ag.id}/owners"
                        )
                        ag.owners = owners_resp.get("value", [])
                    with contextlib.suppress(Exception):
                        sponsors_resp = await graph.get(
                            f"/servicePrincipals/{ag.id}/sponsors"
                        )
                        ag.sponsors = sponsors_resp.get("value", [])
                    with contextlib.suppress(Exception):
                        ara_resp = await graph.get(
                            f"/servicePrincipals/{ag.id}"
                            "/appRoleAssignments"
                        )
                        ag.app_role_assignments = [
                            AppRoleAssignment.model_validate(a)
                            for a in ara_resp.get("value", [])
                        ]
                    with contextlib.suppress(Exception):
                        grants_resp = await graph.get(
                            f"/servicePrincipals/{ag.id}"
                            "/oauth2PermissionGrants"
                        )
                        ag.oauth2_permission_grants = grants_resp.get(
                            "value", []
                        )
                    agent_identities.append(ag)
                _ok(
                    "Agent identities",
                    f"{len(agent_identities)} agents",
                )
            except _EXPECTED_FETCH_ERRORS as exc:
                logger.debug("Agent identities fetch failed", exc_info=exc)
                _fail("Agent identities", str(exc))

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
            agent_identities=agent_identities,
            agent_identity_blueprints=agent_blueprints,
            agent_identity_blueprint_principals=agent_bp_principals,
            granted_permissions=granted_permissions,
        )

        # --- Discover and run checks ---
        checks = engine.discover()
        if not quiet:
            console.print(f"\nRunning {len(checks)} security checks...\n")

        engine.build_execution_order()
        findings = engine.execute(context)

        return findings, org_display_name, org_primary_domain


def _print_finding(finding: Finding, verbose: bool, *, tag: str = "") -> None:
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
    console.print(f" {icon}  {finding.check_id:18s} {finding.title}{tag}")
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
    baseline: Annotated[
        str | None,
        typer.Option(
            "--baseline",
            help="Path to baseline file for comparison (default: .entralint-baseline.json)",
        ),
    ] = None,
    update_baseline: Annotated[
        bool,
        typer.Option(
            "--update-baseline",
            help="Save current scan as the new baseline",
        ),
    ] = False,
    fail_on_new: Annotated[
        bool,
        typer.Option(
            "--fail-on-new",
            help="Exit non-zero only for NEW findings (not in baseline)",
        ),
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
        tenant = os.environ.get("ENTRALINT_TENANT_ID")
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
    # Auto-detect CI/CD auth method from environment variables.
    # Priority: 1) workload identity federation / DefaultAzureCredential,
    #           2) client secret or certificate, 3) cached interactive token.
    ci_secret = os.environ.get("ENTRALINT_CLIENT_SECRET")
    ci_cert = os.environ.get("ENTRALINT_CLIENT_CERTIFICATE_PATH")
    use_default_cred = (
        os.environ.get("ENTRALINT_USE_DEFAULT_CREDENTIAL", "").lower()
        in ("1", "true", "yes")
    )
    # Also detect GitHub Actions OIDC or Azure-hosted managed identity
    has_wif = bool(
        os.environ.get("AZURE_FEDERATED_TOKEN_FILE")
        or os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    )
    has_managed_id = bool(
        os.environ.get("IDENTITY_ENDPOINT")
        or os.environ.get("MSI_ENDPOINT")
    )

    if use_default_cred or has_wif or has_managed_id:
        provider = AuthProvider(
            tenant_id=tenant,
            method=AuthMethod.DEFAULT_CREDENTIAL,
        )
        try:
            token = provider.acquire_token_default_credential()
        except AuthenticationError as exc:
            console.print(f"[red]DefaultAzureCredential auth failed:[/red] {exc}")
            raise typer.Exit(code=1) from None
    elif ci_secret or ci_cert:
        provider = AuthProvider(
            tenant_id=tenant,
            method=AuthMethod.CLIENT_CREDENTIALS,
            client_secret=ci_secret,
            client_certificate_path=ci_cert,
        )
        try:
            token = provider.acquire_token_client_credentials()
        except AuthenticationError as exc:
            console.print(f"[red]Client credentials auth failed:[/red] {exc}")
            raise typer.Exit(code=1) from None
    else:
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
    custom_dirs = (
        [Path(d) for d in cfg.custom_checks_dirs]
        if cfg and cfg.custom_checks_dirs
        else None
    )
    engine = CheckEngine(custom_checks_dirs=custom_dirs)
    # Apply filters after discovery
    severity_list = [s.strip() for s in severity.split(",")] if severity else None
    check_ids = [c.strip() for c in checks.split(",")] if checks else None

    # Merge config-level exclusions into check_ids filter
    exclude_set: set[str] = set()
    if cfg:
        exclude_set.update(cfg.exclude_checks)
        exclude_set.update(r.check for r in cfg.suppress)

    # --- Run scan ---
    findings, tenant_display_name, tenant_primary_domain = asyncio.run(
        _fetch_and_scan(
            token=token,
            engine=engine,
            quiet=suppress_console,
            tenant_id=tenant,
            no_cache=no_cache,
            offline=offline,
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

    # --- Baseline: save / compare ---
    baseline_path = baseline or (cfg.baseline if cfg else None)
    delta = None

    if update_baseline:
        out_path = baseline_path or DEFAULT_BASELINE_FILE
        saved = save_baseline(findings, out_path)
        if not suppress_console:
            fail_count = sum(1 for f in findings if f.status == Status.FAIL)
            console.print(
                f"\n[green]Baseline saved:[/green] {saved} "
                f"({fail_count} findings)"
            )
    elif baseline_path:
        try:
            snap = load_baseline(baseline_path)
            delta = compare(findings, snap)
        except FileNotFoundError:
            if not suppress_console:
                console.print(
                    f"[yellow]Baseline file not found: {baseline_path} "
                    "(run with --update-baseline to create one)[/yellow]"
                )

    # --- Stream findings to console ---
    if not suppress_console:
        # Build a set of NEW fingerprints for annotation.
        from entralint.core.baseline import _fingerprint

        new_fps: set[str] = set()
        if delta:
            new_fps = {_fingerprint(f) for f in delta.new}

        for finding in findings:
            tag = ""
            if delta and finding.status == Status.FAIL:
                fp = _fingerprint(finding)
                tag = " [red bold]NEW[/red bold]" if fp in new_fps else ""
            _print_finding(finding, verbose, tag=tag)

    # --- Summary ---
    if not suppress_console:
        display_scan_summary(findings)
        if delta:
            display_baseline_delta(delta)

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
        # Build tenant label: "Display Name (domain)" or just the guid
        tenant_label = tenant or "Unknown"
        if tenant_display_name and tenant_primary_domain:
            tenant_label = f"{tenant_display_name} ({tenant_primary_domain})"
        elif tenant_primary_domain:
            tenant_label = tenant_primary_domain
        elif tenant_display_name:
            tenant_label = f"{tenant_display_name} ({tenant})"
        report_text = format_html(
            findings, tenant_id=tenant_label, check_metadata=meta_lookup,
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
    # When --update-baseline is used, always exit 0.
    if update_baseline:
        raise typer.Exit(code=0)

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

    # When --fail-on-new is set and we have a delta, only NEW findings count.
    check_findings = delta.new if fail_on_new and delta else findings

    has_failures = any(
        f.status == Status.FAIL and SEVERITY_RANK.get(f.severity, 99) <= threshold_rank
        for f in check_findings
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
