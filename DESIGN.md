# EntraLint: Technical Design Document

**An Open-Source Entra ID Security Linter**

*Version 2.0 — March 2026*

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Architecture Overview and Tech Stack](#architecture-overview-and-tech-stack)
3. [Authentication Model](#authentication-model)
4. [Graph API Permissions](#graph-api-permissions)
5. [Multi-Tenant App Registration](#multi-tenant-app-registration)
6. [Security Check Library](#security-check-library)
7. [Rules Engine Architecture](#rules-engine-architecture)
8. [Data Collection and Caching](#data-collection-and-caching)
9. [Graph API Scanning Sequence and Rate Limit Management](#graph-api-scanning-sequence-and-rate-limit-management)
10. [Error Taxonomy and Resilience](#error-taxonomy-and-resilience)
11. [CLI UX Design](#cli-ux-design)
12. [Web UI Design](#web-ui-design)
13. [Multi-Tenant Support Model](#multi-tenant-support-model)
14. [Report Generation Formats](#report-generation-formats)
15. [Extensibility and Plugin System](#extensibility-and-plugin-system)
16. [Agentic Identity Security](#agentic-identity-security)
    - [Detailed Check Reference](#detailed-check-reference)
17. [GitHub Repository Structure](#github-repository-structure)
18. [Testing Strategy](#testing-strategy)

---

## Executive Summary

EntraLint is an open-source, CLI-first security linter for Microsoft Entra ID that provides comprehensive misconfiguration detection, policy-as-code rule definitions, multi-tenant scanning, and a modern developer experience. It is built in Python with a rules engine architecture, structured output (SARIF, JSON, HTML), and CI/CD integration as core design goals.

This document provides the complete technical specification for implementation.

---

## Architecture Overview and Tech Stack

### Why Python

The tech stack centers on **Python 3.11+** as the primary runtime.

| Factor | Python | TypeScript | Go | PowerShell |
|--------|--------|------------|-----|-----------|
| Azure SDK maturity | ★★★★★ | ★★★★ | ★★★ | ★★★★ |
| Security tool precedent | ★★★★★ | ★★ | ★★★ | ★★ |
| Contributor pool size | ★★★★★ | ★★★★ | ★★★ | ★★★ |
| CLI distribution | ★★★ | ★★★ | ★★★★★ | ★★ |
| Cross-platform | ★★★★★ | ★★★★ | ★★★★★ | ★★★ |

Azure CLI itself is built in Python, every major comparable security scanner uses Python (Prowler, Checkov, ScoutSuite), the MSAL Python library is mature and feature-complete, and the security community contributor pool is largest in Python.

Python's distribution complexity (vs. Go's single binary) is mitigated through `pipx` for isolated installs, Docker images for container environments, and optional PyInstaller binaries.

### Complete tech stack

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Language | Python 3.11+ | Ecosystem dominance, MSAL maturity, contributor pool |
| Auth library | MSAL Python (direct) | Finer control than `azure-identity` for multi-tenant token management |
| CLI framework | Typer + Rich | Modern type-hint CLI with beautiful terminal output |
| Data models | Pydantic v2 | Type safety, serialization, validation |
| HTTP client | httpx (async) | Async support for parallel API calls, HTTP/2 |
| Rules engine | Python classes + JSON metadata | Proven at scale by Prowler (500+ checks) |
| Report templating | Jinja2 | HTML/Markdown generation with embedded data |
| Charts | Chart.js (embedded in HTML) | Client-side, no server dependency |
| Web dashboard | FastAPI + HTMX + Jinja2 | Python-centric stack, minimal JS, server-driven |
| Database (web) | SQLite (local) / PostgreSQL (SaaS) | Zero-config local, scalable SaaS |
| CSS | TailwindCSS | Utility-first, compiled or CDN |
| Testing | pytest + pytest-asyncio | Standard Python testing with async support |
| Package management | uv | Significantly faster dependency resolution than Poetry; growing ecosystem adoption and reproducible builds |
| Type checking | mypy (strict) | Catch bugs before runtime |
| Linting | Ruff | Fast Python linter/formatter |
| PDF generation | Playwright | Generate PDF from HTML report; avoids WeasyPrint's heavy native dependencies (cairo, pango) |

---

## Authentication Model

EntraLint supports three authentication flows, each targeting a specific deployment scenario. The architecture wraps MSAL Python directly (not `azure-identity`) for maximum control over token caching, refresh behavior, and multi-tenant token isolation.

### Flow 1: Authorization Code with PKCE (default interactive flow)

This is the **primary flow** for interactive CLI usage. Authorization code flow with PKCE is the security best practice for public client applications and avoids the phishing risk inherent in device code flow.

```
entralint login --tenant contoso.onmicrosoft.com
# → Opens system browser for auth + MFA
# → Listens on localhost:<random-port> for redirect
# → Token cached to ~/.entralint/cache/<tenant_id>.json
```

The CLI spawns a local HTTP listener on a random ephemeral port, opens the system browser to the Entra authorization endpoint with PKCE challenge, and receives the authorization code via localhost redirect. MSAL's `acquire_token_interactive()` handles this flow natively.

This flow uses delegated permissions, meaning the scanning user must hold an appropriate Entra role (Security Reader or Global Reader minimum). The tool validates the user's role assignment at login time and warns if insufficient permissions are detected.

### Flow 1b: Device Code (fallback for headless/SSH sessions)

Device code is available **only** as an explicit fallback when a browser is not available (SSH sessions, remote servers, containers):

```
entralint login --tenant contoso.onmicrosoft.com --method device_code
# → "To sign in, visit https://microsoft.com/devicelogin and enter code ABCD1234"
# → Token cached to ~/.entralint/cache/<tenant_id>.json
```

> **Design note:** EntraLint's own check library flags unblocked device code flow as a security risk (CIS 5.2.2.12). Using it as the default auth method would contradict the tool's own recommendations. Authorization code with PKCE is the default; device code requires explicit `--method device_code`.

### Flow 2: Client Credentials for CI/CD and automation

For scheduled scans, GitHub Actions, and Azure DevOps pipelines. Uses application permissions with certificate-based credentials (preferred over secrets).

The scan command auto-detects `ENTRALINT_CLIENT_SECRET` or `ENTRALINT_CLIENT_CERTIFICATE_PATH` environment variables and switches to client credentials flow — no `entralint login` needed.

```yaml
# GitHub Actions — using the reusable action
- name: EntraLint Security Scan
  uses: bgdnext64/EntraLint@main
  with:
    tenant-id: ${{ secrets.ENTRALINT_TENANT_ID }}
    client-id: ${{ secrets.ENTRALINT_CLIENT_ID }}
    client-secret: ${{ secrets.ENTRALINT_CLIENT_SECRET }}
    fail-on: high
```

```yaml
# GitHub Actions — manual invocation
- name: EntraLint Security Scan
  env:
    ENTRALINT_TENANT_ID: ${{ secrets.TENANT_ID }}
    ENTRALINT_CLIENT_ID: ${{ secrets.CLIENT_ID }}
    ENTRALINT_CLIENT_SECRET: ${{ secrets.CLIENT_SECRET }}
  run: entralint scan --fail-on critical --quiet -f sarif --output-file results.sarif
```

The reusable action (`uses: bgdnext64/EntraLint@main`) handles Python/uv setup, runs the scan, and uploads SARIF to GitHub Code Scanning automatically. See `action.yml` for the full input/output specification.

### Flow 3: Managed Identity for Azure-hosted deployments

When running inside Azure (Functions, App Service, AKS, Automation), the tool detects `DefaultAzureCredential` automatically — no credentials to configure. Permissions must be assigned to the managed identity via PowerShell since no portal UI exists for this.

---

## Graph API Permissions

### Required application permissions (minimum, read-only)

| Permission | Purpose |
|-----------|---------|
| `Directory.Read.All` | Users, groups, service principals, org config, OAuth2 grants |
| `Policy.Read.All` | CA policies, named locations, auth methods policy, cross-tenant policy, authorization policy, security defaults |
| `AuditLog.Read.All` | Sign-in logs, directory audits, auth methods reporting |
| `Application.Read.All` | App registrations, credentials, secret expiry |
| `RoleManagement.Read.Directory` | Directory role assignments, PIM schedules |
| `UserAuthenticationMethod.Read.All` | Per-user authentication method registrations |
| `IdentityRiskEvent.Read.All` | Risk detections from Identity Protection |
| `IdentityRiskyUser.Read.All` | Risky user flags |
| `IdentityRiskyServicePrincipal.Read.All` | Risky service principal detection |

### Extended permissions (optional)

`Reports.Read.All`, `SecurityAlert.Read.All`, `AccessReview.Read.All`, `CrossTenantInformation.ReadBasic.All`

### Permission grant scripts

The `entralint permissions` command introspects all discovered checks and aggregates their `RequiredPermissions` metadata. It outputs:

- **Table** (default) — list of permissions, how many checks depend on each, and the well-known Graph app role GUID
- **PowerShell** — complete `Microsoft.Graph` SDK script using `New-MgServicePrincipalAppRoleAssignment` with idempotent checks
- **Azure CLI** — bash script using `az rest` to POST `appRoleAssignments`

Both script formats include the stable app role GUIDs for each permission, handle already-granted roles, and require only `--client-id` to be fully runnable.

### License-gated endpoints

| Feature | Required License | Behavior When Missing |
|---------|-----------------|----------------------|
| Sign-in logs (`/auditLogs/signIns`) | Entra ID P1+ | Checks gracefully skipped with informational warning |
| Identity Protection (`/identityProtection/*`) | Entra ID P2 | Checks gracefully skipped with informational warning |

See [Error Taxonomy and Resilience](#error-taxonomy-and-resilience) for the full degradation model.

---

## Multi-Tenant App Registration

For MSP and multi-tenant scenarios, EntraLint registers as a multi-tenant app ("Accounts in any organizational directory"). Each customer tenant admin grants consent via:

```
https://login.microsoftonline.com/{target-tenant}/adminconsent?client_id={entralint-client-id}
```

Token acquisition then uses tenant-specific endpoints (the `/common/` endpoint does not work for client credentials flow). Each tenant gets its own MSAL `ConfidentialClientApplication` instance with an isolated `SerializableTokenCache`.

---

## Security Check Library

### 70 rules across eight categories

The check library launches with 70 rules organized into eight categories, mapped to CIS Microsoft 365 Foundations Benchmark v5/v6, CISA SCuBA Entra ID Baseline (BOD 25-01), and Microsoft best practices.

### Check distribution by severity

| Category | Critical | High | Medium | Low | Total |
|----------|----------|------|--------|-----|-------|
| Conditional Access gaps | 3 | 5 | 3 | 0 | **13** |
| MFA coverage | 1 | 5 | 3 | 0 | **10** |
| Privileged role management | 4 | 3 | 1 | 0 | **10** |
| App & service principal security | 3 | 5 | 4 | 0 | **12** |
| Guest account hygiene | 1 | 2 | 3 | 1 | **7** |
| Inactive/stale accounts | 0 | 2 | 3 | 0 | **5** |
| Authentication policies | 1 | 1 | 4 | 2 | **8** |
| Cross-tenant & B2B | 0 | 2 | 3 | 0 | **5** |
| **Total** | **13** | **25** | **24** | **3** | **70** |

### The 15 Critical-severity checks (implement first)

These represent the highest-impact attack vectors based on real-world breach analysis:

1. **No CA policy requiring MFA for all users** — The Midnight Blizzard attack exploited exactly this gap on a test tenant. Checks that at least one enabled policy targets All Users + All Cloud Apps with MFA grant control. (`GET /identity/conditionalAccess/policies`)

2. **No CA policy blocking legacy authentication** — Legacy auth protocols (Exchange ActiveSync, IMAP, POP3) bypass MFA entirely. Checks for a policy blocking `exchangeActiveSync` and `other` client app types. (CIS 5.2.2.3, CISA MS.AAD.5.1)

3. **No phishing-resistant MFA for admins** — Admin roles must require FIDO2 or Windows Hello for Business via authentication strength grant controls. (CIS 5.2.2.5, CISA MS.AAD.3.2)

4. **All CA policies in report-only mode** — A tenant with policies only in audit mode has zero enforcement. Checks `state` field for at least one `enabled` policy.

5. **Users not MFA-capable** — All member users must be registered for at least one MFA method. (`GET /reports/authenticationMethods/userRegistrationDetails?$filter=isMfaCapable eq false`)

6. **Permanent Global Admin assignments** — Should use PIM eligible assignments with maximum 2 permanent break-glass accounts. Cross-references `roleAssignmentScheduleInstances` against `roleEligibilityScheduleInstances`.

7. **Too many Global Admins** — More than 4 active Global Administrators creates excessive blast radius. (CIS 1.1.3, CISA MS.AAD.7.2)

8. **No PIM configured** — All highly privileged roles should be managed through Privileged Identity Management. Checks for role eligibility schedules.

9. **No approval required for GA/PRA activation** — Global Admin and Privileged Role Admin PIM activation must require approval. Checks `roleManagementPolicies` rules.

10. **No emergency access accounts** — Must have 2+ break-glass accounts (cloud-only, excluded from CA, with Global Admin). Heuristic detection based on CA exclusions.

11. **Apps with high-privilege Graph permissions** — Detects applications holding `RoleManagement.ReadWrite.All`, `Application.ReadWrite.All`, `Mail.ReadWrite` (unconstrained), `Directory.ReadWrite.All`. Cross-references `servicePrincipals/{id}/appRoleAssignments`.

12. **Service principals with directory role assignments** — SPs holding Global Admin, Application Admin, or similar roles represent catastrophic blast radius.

13. **Users who own apps with privileged permissions** — Non-admin users owning privileged applications create escalation paths (the exact Midnight Blizzard vector). Cross-references `applications/{id}/owners` with permission analysis.

14. **Guest users with privileged roles** — External accounts should never hold administrative directory roles. (CISA MS.AAD.8.1)

15. **Password hash sync not enabled for hybrid** — Required for Entra ID Protection leaked credential detection. (CIS 5.1.8.1, CISA MS.AAD.1.1)

### Sample checks across other categories

**Conditional Access — High severity:** Device code flow not blocked (CIS 5.2.2.12), no sign-in risk policy blocking high/medium risk, no user risk policy, excessive CA policy exclusions beyond break-glass accounts, guest users excluded from all CA policies, no managed device requirement for admins.

**MFA — High severity:** Per-user MFA still enabled instead of CA-based (CIS 5.1.2.1), SMS/voice MFA methods still allowed (CIS 5.2.3.5), Authenticator not configured for number matching, custom banned password list not configured, trusted IPs configured for MFA bypass.

**App Security — High severity:** Apps with expiring/expired client secrets, apps with long-lived secrets (>1 year), app registrations with no owners, user consent to apps allowed without restriction (CIS 5.1.5.1), stale service principals with valid credentials (no sign-in for 90+ days).

**Guest Hygiene — High severity:** Guest access level too permissive (should be restricted to own profile via `guestUserRoleId`), anyone can invite guests (should be limited to Guest Inviter role).

---

## Rules Engine Architecture

### Check structure

Each check lives in its own directory with two files:

```
entralint/checks/conditional_access/ca_mfa_required_all_users/
├── ca_mfa_required_all_users.py           # Check logic
└── ca_mfa_required_all_users.metadata.json # Metadata
```

### Check class design

The Python check class inherits from `BaseCheck` and implements an `execute()` method:

```python
from entralint.core.check import BaseCheck, Finding, Severity, Status

class CaMfaRequiredAllUsers(BaseCheck):
    def execute(self, context: TenantContext) -> list[Finding]:
        policies = context.conditional_access_policies
        has_mfa_all_users = any(
            p.state == "enabled"
            and "All" in (p.conditions.users.include_users or [])
            and "mfa" in (p.grant_controls.built_in_controls or [])
            for p in policies
        )

        if not has_mfa_all_users:
            return [Finding(
                check_id=self.metadata.check_id,
                status=Status.FAIL,
                severity=Severity.CRITICAL,
                resource_type="ConditionalAccessPolicy",
                resource_id="tenant-wide",
                title="No CA policy requires MFA for all users",
                description="No enabled Conditional Access policy enforces MFA for all users across all cloud apps.",
                remediation="Create a CA policy targeting All Users + All Cloud Apps with MFA grant control.",
            )]
        return [Finding(check_id=self.metadata.check_id, status=Status.PASS, ...)]
```

### Check metadata with versioning

Each check includes a `check_version` field for tracking logic changes. When check logic changes (e.g., threshold adjustment), the version is bumped. This ensures scan comparison reports can flag when a finding change was caused by a check update vs. a real configuration change.

```json
{
    "CheckID": "entraid_ca_001",
    "CheckVersion": "1.0.0",
    "CheckTitle": "Ensure MFA is required for all users via Conditional Access",
    "ServiceName": "ConditionalAccess",
    "Severity": "CRITICAL",
    "ResourceType": "ConditionalAccessPolicy",
    "Description": "Verifies that at least one enabled CA policy enforces MFA for all users and all cloud apps.",
    "Risk": "Without universal MFA enforcement, compromised credentials allow direct account takeover. This was the exact attack vector in the Midnight Blizzard breach.",
    "Remediation": {
        "Recommendation": "Create a Conditional Access policy targeting All Users with All Cloud Apps scope and MFA grant control.",
        "Url": "https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-all-users-mfa"
    },
    "Frameworks": {
        "CIS_M365_v5": ["5.2.2.2"],
        "CISA_SCuBA": ["MS.AAD.3.1"],
        "NIST_800-53": ["IA-2"]
    },
    "GraphAPIEndpoints": ["/identity/conditionalAccess/policies"],
    "RequiredPermissions": ["Policy.Read.All"],
    "RequiredLicense": null,
    "DependsOn": []
}
```

### Check dependency graph

Some checks logically depend on others. The `DependsOn` metadata field declares these relationships, enabling the engine to:

1. **Skip gracefully** when a prerequisite check fails (e.g., "no approval required for GA activation" is irrelevant if "no PIM configured" already fails)
2. **Share computed intermediate results** via the `TenantContext.computed` dict (e.g., an "effective privilege set" computed once and reused)
3. **Order execution** to ensure dependencies run first

```json
{
    "CheckID": "entraid_priv_004",
    "CheckTitle": "No approval required for Global Admin PIM activation",
    "DependsOn": ["entraid_priv_003"],
    "...": "..."
}
```

The engine builds a DAG from `DependsOn` declarations and executes checks in topological order. If a dependency fails, dependent checks are reported as `Status.SKIPPED` with a reason referencing the failed prerequisite.

```python
class CheckEngine:
    def _build_execution_order(self, checks: list[BaseCheck]) -> list[BaseCheck]:
        """Topological sort of checks based on DependsOn metadata."""
        graph = {c.metadata.check_id: c for c in checks}
        visited, order = set(), []

        def visit(check_id: str):
            if check_id in visited:
                return
            visited.add(check_id)
            for dep_id in graph[check_id].metadata.depends_on:
                if dep_id in graph:
                    visit(dep_id)
            order.append(graph[check_id])

        for check_id in graph:
            visit(check_id)
        return order
```

### Check discovery and execution pipeline

At runtime, the engine auto-discovers all checks by scanning the `checks/` directory tree using Python's `importlib`:

1. **Discovery** — Scan `checks/` directories, import modules, instantiate check classes
2. **Filtering** — Apply user-selected filters (severity, category, framework, specific check IDs)
3. **Permission validation** — Compare each check's `RequiredPermissions` against actual granted permissions; skip checks with warnings where permissions are insufficient (see [Error Taxonomy](#error-taxonomy-and-resilience))
4. **License validation** — Compare each check's `RequiredLicense` against detected tenant license; skip checks with informational messages where license is insufficient
5. **Dependency ordering** — Build DAG and topologically sort remaining checks
6. **Data collection** — Fetch required Graph API data based on aggregated `RequiredPermissions` across selected checks (fetch each endpoint once, share across checks)
7. **Execution** — Run each check's `execute()` method with the `TenantContext` containing cached API responses
8. **Aggregation** — Collect all `Finding` objects into a `ScanReport`
9. **Output** — Render to selected format(s)

### Custom checks

Users create custom checks by adding new directories to `~/.entralint/custom_checks/` or a project-local `.entralint/checks/` directory. The engine discovers these alongside built-in checks.

### Custom compliance frameworks

Organizations define custom frameworks as JSON mapping files:

```json
{
    "FrameworkName": "Contoso Security Baseline v2",
    "Requirements": [
        {
            "Id": "CSB-001",
            "Description": "All users must have MFA enforced via Conditional Access",
            "CheckIDs": ["entraid_ca_001", "entraid_mfa_002"]
        }
    ]
}
```

---

## Data Collection and Caching

### The problem with fetch-everything-every-time

For large tenants (10k+ users, 1k+ apps), fetching all Graph data on every scan is slow and expensive against rate limits. The data collection layer addresses this with local caching and incremental fetching.

### Local cache layer

A SQLite-backed cache stores the last Graph API response per endpoint per tenant, with configurable TTL:

```python
class GraphCache:
    """SQLite-backed cache for Graph API responses."""

    DEFAULT_TTL = {
        "policies": timedelta(minutes=15),    # CA policies change infrequently
        "organization": timedelta(hours=1),    # Org config is near-static
        "users": timedelta(minutes=30),        # User list changes moderately
        "applications": timedelta(minutes=30), # App registrations
        "signInActivity": timedelta(hours=4),  # Expensive, long TTL
        "auditLogs": timedelta(minutes=5),     # Freshness matters
    }

    def get(self, tenant_id: str, endpoint: str) -> CachedResponse | None:
        """Return cached response if within TTL, else None."""
        ...

    def put(self, tenant_id: str, endpoint: str, data: dict, etag: str | None = None):
        """Store response with timestamp and optional ETag."""
        ...
```

### Cache modes

| Flag | Behavior |
|------|----------|
| `--no-cache` | Bypass cache entirely, fetch everything fresh |
| `--offline` | Run checks against cached data only, no API calls. Useful for iterating on custom checks |
| *(default)* | Use cache within TTL, fetch expired data |
| `--refresh <endpoint>` | Force refresh specific data category (e.g., `--refresh users,policies`) |

### Incremental delta queries

For `/users` and `/servicePrincipals`, the cache stores the `$deltatoken` from the previous fetch and uses it for subsequent scans to retrieve only changed records. This dramatically reduces API calls for large tenants:

```python
async def fetch_users_incremental(self, tenant_id: str) -> list[User]:
    cached = self.cache.get(tenant_id, "users")
    if cached and cached.delta_token:
        # Fetch only changes since last scan
        delta_users = await self.graph.get(
            f"/users/delta?$deltatoken={cached.delta_token}&$select=..."
        )
        return self._merge_delta(cached.data, delta_users)
    else:
        # Full fetch
        return await self.graph.get_all_pages("/users?$select=...")
```

---

## Graph API Scanning Sequence and Rate Limit Management

### Recommended API call sequence

Data is fetched in order optimized for dependency resolution and rate limit efficiency:

| Order | Endpoint | Resource Units | Purpose |
|-------|----------|---------------|---------|
| 1 | `GET /organization` | 2 | Tenant baseline config |
| 2 | `GET /policies/identitySecurityDefaultsEnforcementPolicy` | 2 | Security defaults status |
| 3 | `GET /policies/authenticationMethodsPolicy` | 2 | Allowed auth methods |
| 4 | `GET /policies/authorizationPolicy` | 2 | User defaults, guest settings |
| 5 | `GET /policies/crossTenantAccessPolicy` | 2 | B2B settings |
| 6 | `GET /identity/conditionalAccess/policies` | 2 | All CA policies |
| 7 | `GET /identity/conditionalAccess/namedLocations` | 2 | Location definitions |
| 8 | `GET /users?$select=id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime` | 2/page | All users (without `signInActivity`) |
| 9 | `GET /applications?$select=id,displayName,appId,passwordCredentials,keyCredentials,signInAudience` | 2/page | App registrations + credentials |
| 10 | `GET /servicePrincipals?$select=id,displayName,appId,servicePrincipalType,accountEnabled` | 2/page | Service principals (max 100/page) |
| 11 | `GET /roleManagement/directory/roleAssignments?$expand=principal` | 2 | Privileged role assignments |
| 12 | `GET /oauth2PermissionGrants` | 2 | Delegated permission grants |
| 13 | `GET /reports/authenticationMethods/userRegistrationDetails` | — | MFA registration status |
| 14 | `GET /identityProtection/riskyUsers` | — | Users at risk (P2) |
| 15 | `GET /auditLogs/signIns?$filter=createdDateTime ge {7daysAgo}` | — | Recent sign-ins (P1+) |

### Solving the `signInActivity` problem

The `signInActivity` property on users triggers aggressive throttling (10 requests per minute). For tenants with >5,000 users this is a serious bottleneck.

**Solution: Decouple `signInActivity` from the main user fetch.**

1. The primary user fetch (`Order 8`) does **not** include `signInActivity` in `$select`
2. `signInActivity` is fetched separately and **only when checks require it** (stale account checks)
3. Use batch requests (`POST /$batch`) to fetch `signInActivity` for users in batches of 20, with explicit rate limiting at 8 requests per minute (below the 10/min threshold)
4. For very large tenants, use the `GET /reports/getInactiveUsersByApplication` endpoint as an alternative that avoids per-user throttling
5. `signInActivity` results are cached with a 4-hour TTL (this data does not need real-time freshness)

```python
class SignInActivityFetcher:
    """Dedicated fetcher for signInActivity with aggressive rate limiting."""

    MAX_REQUESTS_PER_MINUTE = 8  # Stay below 10/min Graph throttle

    async def fetch(self, user_ids: list[str]) -> dict[str, SignInActivity]:
        """Batch-fetch signInActivity with per-minute rate limiting."""
        results = {}
        for batch in chunked(user_ids, 20):
            async with self._rate_limiter:
                batch_request = self._build_batch(batch)
                responses = await self.graph.post("/$batch", batch_request)
                results.update(self._parse_batch(responses))
        return results
```

### Rate limiting strategy

- **Per-tenant enforcement** — Each tenant has independent rate limit tracking (Graph quotas are per-app-per-tenant)
- **Proactive throttling** — Monitor `x-ms-throttle-limit-percentage` response header; reduce request rate when value exceeds 0.8
- **Exponential backoff** — On 429 responses, honor `Retry-After` header exactly; escalate backoff on consecutive throttles
- **`$select` always** — Include `$select` on every request to reduce ResourceUnit costs by 1 per call
- **`$top=999`** for user/app/SP enumeration to maximize records per page
- **Audit/report endpoint awareness** — These have drastically stricter limits (5 requests per 10 seconds per app per tenant). Apply a separate, more conservative rate limiter for `/auditLogs/*` and `/reports/*` endpoints

---

## Error Taxonomy and Resilience

### Error hierarchy

The system distinguishes between five categories of non-success conditions. Each category produces a distinct status in the scan report, enabling users to understand exactly why a check did not produce a PASS/FAIL finding.

| Status | Meaning | Cause | User Action |
|--------|---------|-------|-------------|
| `PASS` | Check passed | Configuration meets security requirements | None |
| `FAIL` | Check failed | Misconfiguration detected | Remediate per finding |
| `SKIPPED_LICENSE` | Check skipped | Tenant lacks required license (P1/P2) | Upgrade license or suppress check |
| `SKIPPED_PERMISSION` | Check skipped | App lacks required Graph permission | Grant permission or suppress check |
| `SKIPPED_DEPENDENCY` | Check skipped | A prerequisite check failed | Fix the prerequisite first |
| `ERROR` | Check errored | Unexpected API failure during execution | Retry or report bug |

### Pre-scan permission validation

Before executing any checks, the engine introspects the service principal's granted permissions:

```python
class PermissionValidator:
    async def validate(self, graph_client: GraphClient) -> GrantedPermissions:
        """Fetch actual app role assignments for the current service principal."""
        sp = await graph_client.get("/me" if delegated else
            f"/servicePrincipals(appId='{client_id}')/appRoleAssignments")
        granted = {role.resource_display_name + "/" + role.role_name for role in sp}
        return GrantedPermissions(granted=granted)

    def check_coverage(self, checks: list[BaseCheck], granted: GrantedPermissions) -> CheckCoverage:
        """Compare required vs. granted permissions for each check."""
        runnable, skipped = [], []
        for check in checks:
            missing = set(check.metadata.required_permissions) - granted.permissions
            if missing:
                skipped.append((check, missing))
            else:
                runnable.append(check)
        return CheckCoverage(runnable=runnable, skipped=skipped)
```

The scan start summary displays permission coverage:

```
Permission coverage: 65/70 checks runnable
  ⚠ 3 checks skipped: missing IdentityRiskEvent.Read.All (requires P2 license)
  ⚠ 2 checks skipped: missing Reports.Read.All
```

To resolve missing permissions, use `entralint permissions -f powershell --client-id APP_ID` to generate a ready-to-run grant script.

### License detection

The engine queries `GET /subscribedSkus` at scan start to determine the tenant's Entra ID license tier and maps it to feature availability:

| License | Sign-in logs | Identity Protection | PIM | Access Reviews |
|---------|-------------|--------------------|----|----------------|
| Entra ID Free | ✗ | ✗ | ✗ | ✗ |
| Entra ID P1 | ✓ | ✗ | ✗ | ✗ |
| Entra ID P2 | ✓ | ✓ | ✓ | ✓ |

### Transient error handling

| Error | Strategy |
|-------|----------|
| HTTP 429 (throttled) | Honor `Retry-After` header, exponential backoff, max 3 retries |
| HTTP 502/503/504 (transient) | Retry with jitter, max 3 retries, 2s/4s/8s backoff |
| HTTP 401 (token expired) | Refresh token via MSAL `acquire_token_silent()`, retry once |
| HTTP 403 (forbidden) | Mark affected checks as `SKIPPED_PERMISSION`, do not retry |
| Connection timeout | Retry once after 5s, then mark affected checks as `ERROR` |
| Token refresh failure | Abort scan with clear re-authentication instructions |

### Stale/revoked token handling

Mid-scan 401 errors trigger automatic token refresh:

```python
class GraphClient:
    async def _request_with_auth(self, method: str, url: str, **kwargs) -> httpx.Response:
        response = await self._client.request(method, url, headers=self._auth_headers(), **kwargs)
        if response.status_code == 401:
            # Token expired mid-scan — refresh and retry once
            self._token = await self._auth_provider.acquire_token_silent()
            if not self._token:
                raise AuthenticationExpiredError(
                    "Session expired and could not be refreshed. Run 'entralint login' to re-authenticate."
                )
            response = await self._client.request(method, url, headers=self._auth_headers(), **kwargs)
        return response
```

---

## CLI UX Design

The CLI is built with **Typer** (type-hint-based CLI framework by the FastAPI author) and **Rich** (beautiful terminal output). The experience should feel as fast and polished as modern developer tools like Ruff or ESLint.

### Command structure

```
entralint login    [--tenant TENANT] [--method auth_code|device_code|client_credentials]
entralint scan     [--tenant TENANT] [--profile PROFILE] [--checks CHECK_IDS]
                   [--category CATEGORY] [--framework CIS|CISA|NIST]
                   [--severity critical,high] [--output json|html|csv|sarif|md]
                   [--output-file PATH] [--quiet] [--verbose]
                   [--no-cache] [--offline] [--refresh ENDPOINTS]
entralint scan-all [--profile all-tenants]  # Multi-tenant scan
entralint report   [--input scan-results.json] [--format html|pdf]
entralint list-checks    [--category CATEGORY] [--severity SEVERITY]
entralint list-frameworks
entralint show-check     CHECK_ID
entralint permissions [--format table|powershell|azcli] [--client-id CLIENT_ID]
entralint config         [--init] [--add-tenant] [--list-tenants]
entralint cache          [--clear] [--status] [--tenant TENANT]
entralint version
```

### Terminal output design

Real-time findings stream to the console with color-coded severity as checks execute:

```
╭─ EntraLint v0.1.0 ──────────────────────────────────────────╮
│ Tenant: contoso.onmicrosoft.com (3,847 users)                │
│ Profile: default | Checks: 70 | Framework: All               │
│ Permission coverage: 65/70 checks runnable                   │
│ Cache: 4 endpoints cached, 11 will be fetched                │
╰──────────────────────────────────────────────────────────────╯

Collecting data from Microsoft Graph API...
  ✓ Organization settings          [0.3s]
  ✓ Conditional Access policies    [0.8s]  (cached)
  ✓ Users (3,847)                  [2.1s]
  ✓ Applications (142)             [0.6s]
  ✓ Service Principals (891)       [1.4s]
  ✓ Role Assignments               [0.4s]

Running security checks...

 CRITICAL  entraid_ca_001   No CA policy requires MFA for all users

 CRITICAL  entraid_priv_002 6 permanent Global Admin assignments (max: 4)

 HIGH      entraid_app_001  12 apps with secrets expiring within 30 days

 HIGH      entraid_mfa_003  SMS authentication method still enabled

 PASS      entraid_ca_002   Legacy authentication blocked

 PASS      entraid_auth_001 Security defaults disabled (CA in use)

 SKIPPED   entraid_risk_001 Risky users (missing: IdentityRiskyUser.Read.All)
  ...

╭─ Summary ────────────────────────────────────────────────────╮
│                                                               │
│  Checks: 70  Passed: 48  Failed: 17  Warnings: 5  Skipped: 5│
│                                                               │
│  Category              Pass  Fail  Warn Skip                  │
│  ──────────────────────────────────────────                   │
│  Conditional Access      8     3     2    0                   │
│  MFA Coverage            7     2     1    0                   │
│  Privileged Roles        5     4     1    0                   │
│  Applications            8     4     0    0                   │
│  Guest Accounts          6     1     0    0                   │
│  Stale Accounts          4     1     0    2                   │
│  Auth Policies           6     1     1    0                   │
│  Cross-Tenant            4     1     0    3                   │
│                                                               │
│  Report: ./entralint-report-2026-03-18.html                   │
╰──────────────────────────────────────────────────────────────╯
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | All checks passed (or skipped) |
| `1` | Failures found (CI gate trigger) |
| `2` | Execution error (auth failure, unrecoverable API error) |

The `--quiet` flag suppresses console output for CI pipelines (only writes output file). The `--severity` filter enables CI gates at specific thresholds: `entralint scan --severity critical --quiet` exits 1 only on Critical findings.

### First-run experience

The realistic first-run experience from install to report:

```bash
pip install entralint       # ~15 seconds
entralint login             # Opens browser, MFA, ~30 seconds
entralint scan              # 1-3 minutes depending on tenant size
```

**Target: Under 5 minutes from install to first HTML report** — competitive with any tool in the space and achievable for any tenant size.

---

## Web UI Design

The web dashboard provides a visual interface for scan results, trend analysis, and multi-tenant comparison. The architecture uses **FastAPI + HTMX + Jinja2 + TailwindCSS**, keeping the entire stack Python-centric and avoiding a separate frontend build pipeline.

### Why HTMX over React or Svelte

The security dashboard is primarily read-only with filtering, sorting, and drill-down — a pattern perfectly suited to HTMX's HTML-fragment-swap model. HTMX at 14KB gzipped eliminates the need for webpack, npm, or any JavaScript build toolchain. Python developers can build the entire UI using Jinja2 templates with HTMX attributes for dynamic behavior.

### Dashboard features

- **Scan History View:** Timeline of scans per tenant with trend charts showing pass/fail evolution. Chart.js renders donut charts for severity distribution and line charts for historical trends. Click any scan to drill into findings.

- **Findings Explorer:** Filterable table of all findings across tenants. Filters: severity, category, framework, status, tenant. Each finding expands to show description, affected resources, remediation steps, and framework mappings. HTMX powers the filter interactions — clicking a severity badge triggers `hx-get` to fetch a filtered HTML fragment.

- **Tenant Comparison:** Side-by-side comparison of security posture across tenants. Heat map visualization showing which checks pass/fail per tenant. Critical for MSPs managing baseline consistency.

- **Compliance Dashboard:** Framework-specific views (CIS, CISA SCuBA, NIST). Shows percentage coverage per framework section. Exportable compliance reports in PDF.

- **Drift Detection (Pro feature):** Compares current scan against previous baseline. Highlights new failures, resolved issues, and unchanged findings. Alert notifications via webhook, Slack, or Teams.

### Dashboard startup

```bash
entralint serve --port 8080 --data-dir ~/.entralint/scans/
# Opens http://localhost:8080 with the dashboard
# Reads scan results from local SQLite database
```

For production deployments, the same FastAPI application deploys to any cloud with PostgreSQL replacing SQLite and authentication added via Entra ID SSO.

---

## Multi-Tenant Support Model

Multi-tenant scanning is a **first-class architectural concern**, not a bolt-on feature.

### Configuration schema — secure by design

The configuration file **enforces secret externalization**. Inline secrets are rejected at parse time with a clear error message.

```yaml
# ~/.entralint/config.yaml
defaults:
  output_format: html
  severity_threshold: high
  checks_exclude: []

tenants:
  contoso-prod:
    tenant_id: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    display_name: "Contoso Production"
    auth_method: client_credentials
    client_id: "app-registration-id"
    # Secrets MUST be env var references, Azure Key Vault URIs, or certificate paths.
    # Inline secret values are rejected at config load time.
    client_secret_env: "CONTOSO_CLIENT_SECRET"  # References env var
    tags: [production, enterprise]

  fabrikam-prod:
    tenant_id: "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
    display_name: "Fabrikam Production"
    auth_method: client_credentials
    client_id: "app-registration-id"
    client_certificate_path: "/path/to/cert.pem"
    tags: [production, msp-client]

profiles:
  all-production:
    filter_tags: [production]
  msp-clients:
    filter_tags: [msp-client]
```

### Secret validation

The config parser rejects any configuration that embeds secrets inline:

```python
class ConfigValidator:
    """Validates tenant configuration with strict secret externalization."""

    SECRET_PATTERNS = re.compile(
        r"^[a-zA-Z0-9+/=]{20,}$|"  # Base64-like strings
        r"^[a-f0-9]{32,}$|"         # Hex strings
        r"^ey[a-zA-Z0-9]"           # JWT-like tokens
    )

    ALLOWED_SECRET_FIELDS = {
        "client_secret_env",           # Environment variable name
        "client_secret_keyvault_uri",  # Azure Key Vault URI
        "client_certificate_path",     # File path to certificate
    }

    def validate_tenant(self, tenant_config: dict) -> None:
        # Reject any field named 'client_secret' (must use _env or _keyvault_uri suffix)
        if "client_secret" in tenant_config:
            raise ConfigSecurityError(
                f"Inline 'client_secret' is not allowed. Use 'client_secret_env' "
                f"to reference an environment variable, or 'client_secret_keyvault_uri' "
                f"for Azure Key Vault. This prevents accidental secret exposure in "
                f"version control."
            )
```

### Token isolation

Each tenant gets its own MSAL application instance and dedicated token cache file at `~/.entralint/cache/{tenant_id}.json`. This prevents token leakage between tenants and enables parallel scanning with independent rate limit tracking.

### Fully async multi-tenant scanning

Multi-tenant scanning uses `asyncio.gather()` to match the async httpx Graph client, avoiding the thread/async mismatch of `ThreadPoolExecutor`:

```python
class TenantManager:
    async def scan_all(self, profile: str) -> AggregateReport:
        tenants = self.resolve_profile(profile)
        # Use asyncio.gather for true async parallelism,
        # matching the async httpx Graph client
        semaphore = asyncio.Semaphore(4)  # Limit concurrent tenant scans

        async def scan_with_limit(tenant: TenantConfig) -> TenantReport:
            async with semaphore:
                return await self.scan_tenant(tenant)

        results = await asyncio.gather(
            *(scan_with_limit(t) for t in tenants),
            return_exceptions=True,
        )

        # Separate successes from failures
        reports = []
        errors = []
        for tenant, result in zip(tenants, results):
            if isinstance(result, Exception):
                errors.append((tenant, result))
            else:
                reports.append(result)

        return self.aggregate(reports, errors)
```

Rate limiting is enforced per-tenant (respecting Graph API's per-app-per-tenant quotas) with exponential backoff and `Retry-After` header honoring. The `x-ms-throttle-limit-percentage` response header is monitored, and requests are throttled proactively when the value exceeds 0.8.

### Multi-tenant reporting

Aggregate reports include tenant context on every finding, enable cross-tenant comparison, and highlight configuration drift between tenants that should share the same baseline. The MSP dashboard view groups findings by tenant with roll-up summary statistics.

---

## Report Generation Formats

### Standalone HTML report (primary human-readable output)

A single self-contained file with all CSS, JavaScript, and data embedded inline. The template uses Jinja2 to render:

- Embedded TailwindCSS (compiled, ~10KB)
- Embedded JavaScript for interactive filtering, search, and collapsible sections
- Embedded JSON data blob (`<script>const SCAN_DATA = {...}</script>`) powering client-side interactivity
- Chart.js for summary visualizations (pass/fail donut, severity bar chart)
- Base64-encoded logo

### SARIF output (CI/CD integration)

SARIF 2.1.0 format enables direct integration with GitHub Code Scanning and IDE plugins (VS Code SARIF Viewer). Each finding maps to a SARIF `result` with `ruleId`, `level` (error/warning/note), and `message`. This is the key differentiator for DevSecOps adoption.

### PDF output

Generated via **Playwright** from the HTML report template. Playwright renders the same Jinja2 HTML template in a headless Chromium instance and exports to PDF. This avoids WeasyPrint's heavy native dependencies (cairo, pango, libffi) that cause installation failures across platforms.

```python
class PdfReporter:
    async def generate(self, report: ScanReport, output_path: Path) -> None:
        html_content = self.html_reporter.render(report)
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            page = await browser.new_page()
            await page.set_content(html_content)
            await page.pdf(path=str(output_path), format="A4")
            await browser.close()
```

### Additional formats

- **JSON** — Structured findings for SIEM ingestion, custom automation, and API consumption
- **CSV** — Spreadsheet analysis for compliance teams
- **Markdown** — GitHub/Azure DevOps wiki integration, PR comment summaries

### Output format plugins

New output formats can be registered as plugins following a simple interface: receive a `ScanReport` object, return bytes. This enables community-contributed formats (e.g., AWS Security Hub ASFF, CycloneDX, custom enterprise templates).

---

## Extensibility and Plugin System

### Event hooks and integrations

The scanning engine emits events that plugins can subscribe to:

- `on_scan_start` — Triggered before data collection begins
- `on_finding` — Triggered as each finding is produced
- `on_scan_complete` — Triggered after all checks complete

Built-in hooks include:
- Slack/Teams notification on new Critical findings
- Webhook POST for SIEM integration
- Jira/ServiceNow ticket creation

---

## Agentic Identity Security

### The Problem

AI agents are the fastest-growing identity category in Entra ID. As of March 2026, Microsoft has shipped the **Entra Agent ID** platform with first-class Graph API support (GA v1.0), making agent identities a formally distinct directory object type — not a heuristic overlay on service principals. Copilot Studio agents, Copilot extensions, custom agents built with Semantic Kernel or AutoGen, and third-party AI services now register through dedicated agent identity APIs.

The same governance failures that plague traditional app registrations — excessive permissions, missing owners, stale credentials, shadow IT — are repeating at accelerated pace with agents, compounded by three agent-specific risks:

1. **Broader default permissions.** Agents typically need cross-service access (Mail + Files + Calendar + Teams) to be useful, creating a larger blast radius per identity than single-purpose apps.
2. **Delegation chains.** Agent A calls Agent B with forwarded permissions, creating transitive access paths that are invisible in static permission analysis.
3. **User self-service provisioning.** Copilot Studio and similar platforms enable non-developers to create agents that acquire organizational permissions, bypassing traditional app registration governance.

Microsoft has responded with built-in guardrails — a [blocked permissions list](#blocked-permissions) prevents agents from acquiring the most dangerous Graph API scopes — but no existing scanner provides security posture checks against the agent identity surface. EntraLint is the first tool to provide dedicated agent identity checks using the GA Agent Identity APIs.

### Microsoft Entra Agent ID Architecture

Microsoft Entra Agent ID introduces three first-class resource types in the Graph API, each inheriting from existing identity primitives:

| Resource Type | Inherits From | Purpose | Key Discriminator |
|---|---|---|---|
| **`agentIdentityBlueprint`** | `application` | Template defining an agent type, its permissions, and which scopes agent instances can inherit | `@odata.type: "#microsoft.graph.agentIdentityBlueprint"` |
| **`agentIdentityBlueprintPrincipal`** | `servicePrincipal` | Tenant-specific instantiation of a blueprint — controls tenant-level configuration, owners, and sponsors | `@odata.type: "#microsoft.graph.agentIdentityBlueprintPrincipal"` |
| **`agentIdentity`** | `servicePrincipal` | Individual agent instance that authenticates and acts in the directory | `@odata.type: "#microsoft.graph.agentIdentity"`, `servicePrincipalType: "ServiceIdentity"` |

Key governance concepts introduced with Agent ID:

- **Sponsors.** Users or service principals who can authorize and manage the lifecycle of agent identity instances. Required during blueprint creation. Distinct from owners.
- **Inheritable permissions.** Blueprints define `inheritablePermissions` that control which scopes agent instances can automatically receive — with subtypes `allAllowedScopes`, `enumeratedScopes`, and `noScopes`.
- **Blocked permissions.** Microsoft globally blocks high-risk Graph permissions for agents at the platform level (see [Blocked Permissions](#blocked-permissions) below).
- **`createdByAppId`.** Added to both `application` and `servicePrincipal` resources, enabling provenance tracking for agent identities.

### Graph API Endpoints for Agent Discovery

Agent identity discovery uses dedicated GA endpoints — no heuristic classification required:

| Endpoint | Status | Purpose |
|---|---|---|
| `GET /agentIdentityBlueprints` | GA (v1.0) | List all agent identity blueprints (templates) |
| `GET /agentIdentityBlueprints/{id}` | GA (v1.0) | Get a specific blueprint with properties and relationships |
| `GET /agentIdentityBlueprintPrincipals` | GA (v1.0) | List all blueprint principals (tenant-level blueprint instances) |
| `GET /agentIdentityBlueprintPrincipals/{id}/appRoleAssignments` | GA (v1.0) | Application permissions granted to blueprint principals |
| `GET /agentIdentityBlueprintPrincipals/{id}/oauth2PermissionGrants` | GA (v1.0) | Delegated permissions consented for blueprint principals |
| `GET /agentIdentityBlueprintPrincipals/{id}/owners` | GA (v1.0) | Owners of a blueprint principal |
| `GET /agentIdentityBlueprintPrincipals/{id}/sponsors` | GA (v1.0) | Sponsors who authorize agent lifecycle |
| `GET /agentIdentities` | GA (v1.0) | List all agent identity instances |
| `GET /agentIdentities/{id}` | GA (v1.0) | Get agent identity with properties |
| `GET /agentIdentities/{id}/appRoleAssignments` | GA (v1.0) | Application permissions for a specific agent |
| `GET /agentIdentities/{id}/oauth2PermissionGrants` | GA (v1.0) | Delegated permissions for a specific agent |
| `GET /agentIdentities/{id}/owners` | GA (v1.0) | Owners of an agent identity |
| `GET /agentIdentities/{id}/sponsors` | GA (v1.0) | Sponsors of an agent identity |
| `GET /agentIdentities/{id}/memberOf` | GA (v1.0) | Group/role memberships |
| `GET /agentIdentityBlueprints/{id}/inheritablePermissions` | GA (v1.0) | Scopes that agent instances can automatically inherit |

**Agent registry endpoints** (beta, extending to agent card manifests and collections):

| Endpoint | Status | Purpose |
|---|---|---|
| `GET /agentRegistry/agentCardManifests` | Beta | Agent card manifests in the registry |
| `GET /agentRegistry/agentInstances` | Beta | Agent instances tracked in the registry |
| `GET /agentRegistry/agentCollections` | Beta | Agent collections for grouped management |

**No heuristics needed.** Unlike traditional service principals, agent identities are typed at the API level. EntraLint queries the dedicated agent endpoints directly, eliminating false positives from heuristic classification. The `@odata.type` property and `servicePrincipalType: "ServiceIdentity"` on `agentIdentity` resources provide definitive identification.

### Blocked Permissions

Microsoft globally blocks high-risk Graph API permissions for agents. These permissions cannot be granted to agent identities through Microsoft Graph or the Entra admin center. EntraLint validates that no agent has circumvented these controls.

**Blocked application permissions (❌ = blocked):**

| Permission | Delegated | Application |
|---|---|---|
| `Application.ReadWrite.All` | ➖ | ❌ |
| `AppRoleAssignment.ReadWrite.All` | ➖ | ❌ |
| `Directory.ReadWrite.All` | ❌ | ❌ |
| `Directory.Write.Restricted` | ❌ | ❌ |
| `DelegatedPermissionGrant.ReadWrite.All` | ❌ | ❌ |
| `Files.Read.All` | ➖ | ❌ |
| `Files.ReadWrite.All` | ➖ | ❌ |
| `Group.ReadWrite.All` | ❌ | ❌ |
| `GroupMember.ReadWrite.All` | ❌ | ❌ |
| `RoleManagement.ReadWrite.Directory` | ❌ | ❌ |
| `Sites.FullControl.All` | ➖ | ❌ |
| `Sites.Read.All` | ➖ | ❌ |
| `Sites.ReadWrite.All` | ➖ | ❌ |
| `User.ReadWrite.All` | ❌ | ❌ |
| `User.DeleteRestore.All` | ❌ | ❌ |
| `UserAuthenticationMethod.ReadWrite.All` | ❌ | ❌ |
| `Policy.ReadWrite.CrossTenantAccess` | ➖ | ❌ |
| `AgentIdentity.Create` / `.Create.All` / `.CreateAsManager` | ➖ | ❌ |
| `AgentIdentityBlueprint.ReadWrite.All` / `.Create` / `.CreateAsManager` | ➖ | ❌ |

EntraLint check `agent_003` specifically validates that no agent identity holds a permission from the blocked list — catching misconfigurations, legacy grants, or platform bugs.

### Security Check Library (Agent Category)

The agent category adds 12 checks targeting agent-specific risks. These checks operate on the typed `agentIdentity`, `agentIdentityBlueprint`, and `agentIdentityBlueprintPrincipal` resources returned from the GA endpoints.

| Check ID | Severity | Title | What It Detects |
|---|---|---|---|
| `agent_001` | Critical | Agent with dangerous permissions | Agent identity holding permissions that should be blocked (e.g., `Files.ReadWrite.All`, `User.ReadWrite.All`) — indicates a platform bypass or legacy grant |
| `agent_002` | Critical | Agent blueprint with `allAllowedScopes` inheritance | Blueprint whose `inheritablePermissions` use `allAllowedScopes`, allowing agent instances to inherit any permission without explicit enumeration |
| `agent_003` | High | Agent holding blocked permission | Agent identity granted a permission from Microsoft's globally blocked list — should be impossible but validates platform enforcement |
| `agent_004` | High | Agent with overly broad permission scope | Agent with 5+ application permissions across multiple resource types |
| `agent_005` | High | Agent created by non-admin (`createdByAppId` analysis) | Agent identity whose `createdByAppId` resolves to a non-admin application (e.g., Copilot Studio used by non-admin user) |
| `agent_006` | High | Agent with no owner or sponsor | Agent identity or blueprint with zero owners and zero sponsors — no one accountable for its lifecycle |
| `agent_007` | Medium | External agent blueprint principal | Blueprint principal with `appOwnerOrganizationId` ≠ your tenant — third-party agent operating in your directory |
| `agent_008` | Medium | Agent using client secrets instead of federated credentials | Blueprint using `passwordCredentials` instead of `federatedIdentityCredentials` or managed identity |
| `agent_009` | Medium | Stale agent with valid credentials | Agent identity with no sign-in activity in 90+ days (correlated via `signInLogs`) but `accountEnabled: true` |
| `agent_010` | Medium | Blueprint with no inheritable permission restrictions | Blueprint whose `inheritablePermissions` is empty or unset, giving no signal about intended permission scope |
| `agent_011` | Medium | Agent identity disabled by Microsoft | Agent with `disabledByMicrosoftStatus` set to `DisabledDueToViolationOfServicesAgreement` — potential compromise indicator |
| `agent_012` | Low | Agent without description or documentation | Agent identity or blueprint missing `description` or `info` (marketing/support/terms URLs) — governance gap |

### Detailed Check Reference

#### `entraid_agent_001` — Ensure agent identities do not hold dangerous permissions

| | |
|---|---|
| **Severity** | Critical |
| **Resource Type** | `AgentIdentity` |
| **Required Permission** | `AgentIdentity.Read.All` |
| **Graph Endpoints** | `GET /servicePrincipals/microsoft.graph.agentIdentity`, `GET /servicePrincipals/{id}/appRoleAssignments` |
| **Frameworks** | CIS M365 v5 (5.3.5), CISA SCuBA (MS.AAD.6.1), NIST 800-53 (AC-6) |

**What it detects:** Agent identities that have been granted high-risk application permissions such as `Files.ReadWrite.All`, `User.ReadWrite.All`, or `Directory.ReadWrite.All`. These permissions are on Microsoft's blocked list for new agent grants, so their presence indicates either a legacy grant that predates enforcement, a platform bypass, or a misconfiguration.

**Detection logic:** The check maintains a `DANGEROUS_ROLE_IDS` dictionary mapping 14 well-known Microsoft Graph app role GUIDs to their permission names. For each agent identity, it iterates over `appRoleAssignments` and flags any whose `appRoleId` matches a dangerous GUID. Each matching assignment produces a separate finding identifying the specific permission.

**Dangerous permissions checked (14):**

- `Files.ReadWrite.All`, `Files.Read.All`
- `Sites.FullControl.All`, `Sites.ReadWrite.All`, `Sites.Read.All`
- `User.ReadWrite.All`, `User.DeleteRestore.All`
- `Directory.ReadWrite.All`, `Directory.Write.Restricted`
- `Group.ReadWrite.All`, `GroupMember.ReadWrite.All`
- `RoleManagement.ReadWrite.Directory`
- `Application.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All`

**Risk:** An agent with these permissions can read or modify sensitive data across the entire tenant — user profiles, files, site content, directory objects, or role assignments. A compromised agent token with `RoleManagement.ReadWrite.Directory` grants full privilege escalation.

**Remediation:** Remove the dangerous permission via `DELETE /servicePrincipals/{id}/appRoleAssignments/{assignmentId}`. Replace with least-privilege scopes appropriate for the agent's function. For file access, consider `Files.Read` (delegated, user-scoped) instead of `Files.ReadWrite.All` (application-wide).

---

#### `entraid_agent_002` — Ensure agent blueprints do not use `allAllowedScopes` inheritance

| | |
|---|---|
| **Severity** | Critical |
| **Resource Type** | `AgentIdentityBlueprint` |
| **Required Permission** | `AgentIdentity.Read.All` |
| **Graph Endpoints** | `GET /applications/microsoft.graph.agentIdentityBlueprint`, `GET /applications/{id}/inheritablePermissions` |
| **Frameworks** | CIS M365 v5 (5.1.5.1), NIST 800-53 (AC-6) |

**What it detects:** Agent identity blueprints whose `inheritablePermissions` are configured with `scopeCollectionKind: "allAllowedScopes"`. This setting allows any agent instance created from the blueprint to inherit every permission the blueprint can access, without requiring explicit enumeration of allowed scopes.

**Detection logic:** For each blueprint, iterates the `inheritable_permissions` list. If any `InheritablePermission` object has `scope_collection_kind == "allAllowedScopes"`, the check emits a FAIL finding for that blueprint and breaks (one finding per blueprint, even if multiple inheritable permission entries use `allAllowedScopes`).

**Risk:** `allAllowedScopes` defeats the purpose of the inheritable permissions model. The entire point of `inheritablePermissions` is to restrict which scopes agent instances can pick up from their blueprint — using `allAllowedScopes` makes this restriction vacuous. Any admin granting permissions to the blueprint effectively grants them to every current and future agent instance.

**Remediation:** Update the blueprint's `inheritablePermissions` to use `enumeratedScopes` with an explicit list of allowed scope GUIDs, or `noScopes` if agent instances should not inherit any permissions from the blueprint. Use `PATCH /applications/{blueprintId}` with the updated `inheritablePermissions` collection.

---

#### `entraid_agent_003` — Ensure no agent identity holds a blocked permission

| | |
|---|---|
| **Severity** | High |
| **Resource Type** | `AgentIdentity` |
| **Required Permission** | `AgentIdentity.Read.All` |
| **Graph Endpoints** | `GET /servicePrincipals/microsoft.graph.agentIdentity`, `GET /servicePrincipals/{id}/appRoleAssignments` |
| **Frameworks** | NIST 800-53 (AC-6, AC-3), CISA SCuBA (MS.AAD.6.1) |

**What it detects:** Agent identities holding any permission from Microsoft's official blocked permissions list. While Microsoft's platform enforcement should prevent these grants, this check validates that enforcement is actually working. A match indicates a legacy grant from before enforcement was activated, a platform bug, or a policy circumvention.

**Detection logic:** Maintains a `BLOCKED_APP_ROLE_IDS` dictionary with 19 well-known GUIDs — a superset of the dangerous permissions in `agent_001`. For each agent, iterates `appRoleAssignments` and flags matches. Each match produces an individual finding.

**Blocked permissions checked (19):** All 14 from `agent_001` plus:

- `DelegatedPermissionGrant.ReadWrite.All`
- `Application.ReadWrite.OwnedBy`
- `User.EnableDisableAccount.All`
- `UserAuthenticationMethod.ReadWrite.All`
- `Policy.ReadWrite.CrossTenantAccess`

**Overlap with `agent_001`:** An agent holding `Files.ReadWrite.All` will trigger both `agent_001` (Critical) and `agent_003` (High). This is intentional — `agent_001` focuses on immediate risk severity, while `agent_003` validates platform enforcement. In practice, any `agent_001` finding is also an `agent_003` finding, but `agent_003` casts a wider net.

**Risk:** Blocked permissions enable privilege escalation or tenant-critical changes. `DelegatedPermissionGrant.ReadWrite.All` allows an agent to consent to arbitrary permissions on behalf of users. `UserAuthenticationMethod.ReadWrite.All` allows resetting MFA methods.

**Remediation:** Remove the blocked permission immediately via `DELETE /servicePrincipals/{id}/appRoleAssignments/{assignmentId}`. Investigate how it was assigned — audit `directoryAudits` for the grant event to determine if it was a legacy migration, admin action, or automated process.

---

#### `entraid_agent_004` — Ensure agent identities do not have overly broad permission scope

| | |
|---|---|
| **Severity** | High |
| **Resource Type** | `AgentIdentity` |
| **Required Permission** | `AgentIdentity.Read.All` |
| **Graph Endpoints** | `GET /servicePrincipals/microsoft.graph.agentIdentity`, `GET /servicePrincipals/{id}/appRoleAssignments` |
| **Frameworks** | CIS M365 v5 (5.3.1), NIST 800-53 (AC-6) |

**What it detects:** Agent identities with 5 or more application permission grants (`appRoleAssignments`). A high number of app role assignments indicates the agent accesses multiple resource types (Mail, Files, Users, Groups, etc.), creating a large blast radius.

**Detection logic:** Constant `MAX_APP_ROLE_ASSIGNMENTS = 4`. For each agent, if `len(agent.app_role_assignments) > MAX_APP_ROLE_ASSIGNMENTS`, emit a FAIL finding that includes the count.

**Threshold rationale:** Most well-designed agents need 1–3 permissions (e.g., `Mail.Read` + `Calendars.Read` for a scheduling agent). An agent with 5+ permissions typically indicates either scope creep (dev added permissions during debugging and never removed them) or a multi-purpose agent that should be decomposed into single-purpose identities.

**Risk:** A compromised agent token with many permissions grants the attacker a wide attack surface. Five permissions across Mail, Files, Users, Groups, and Calendar is sufficient to exfiltrate most organizational data.

**Remediation:** Review and remove non-essential permissions. Consider splitting into multiple single-purpose agents, each with minimal permissions for its function. Use `GET /servicePrincipals/{id}/appRoleAssignments` to audit the full list.

---

#### `entraid_agent_005` — Ensure agent identities are created by authorized applications

| | |
|---|---|
| **Severity** | High |
| **Resource Type** | `AgentIdentity` |
| **Required Permission** | `AgentIdentity.Read.All` |
| **Graph Endpoints** | `GET /servicePrincipals/microsoft.graph.agentIdentity` |
| **Frameworks** | CIS M365 v5 (5.1.5.1), NIST 800-53 (CM-3) |

**What it detects:** Agent identities whose `createdByAppId` resolves to an application that is not registered in the tenant. This indicates the agent was created by an external tool (e.g., the Microsoft Graph PowerShell SDK, Graph Explorer, or a third-party platform) rather than a tenant-managed application.

**Detection logic:** Builds a set of `known_app_ids` from `context.applications` (all app registrations in the tenant). For each agent, if `created_by_app_id` is set and does not appear in `known_app_ids`, emit a FAIL finding identifying the external app ID.

**Why this matters:** The `createdByAppId` property records which application called `POST /servicePrincipals/microsoft.graph.agentIdentity` to create the agent. If that application isn't in your tenant's app registrations, you have limited visibility into who created it and why. This is particularly relevant for:

- Agents created via Graph Explorer or SDK during ad-hoc testing
- Agents created by Copilot Studio (which uses Microsoft's own app registration)
- Agents created by third-party agent platforms operating under their own app ID

**Risk:** Agents created by unauthorized applications bypass admin governance review. Without knowing which application created an agent, you cannot enforce app management policies, audit the creation workflow, or attribute the agent to a responsible team.

**Remediation:** Verify the creating application is approved. Map the `createdByAppId` to a specific application using `GET /servicePrincipals?$filter=appId eq '{createdByAppId}'`. Restrict agent creation to authorized applications via Entra ID app management policies.

---

#### `entraid_agent_006` — Ensure all agent identities and blueprints have owners or sponsors

| | |
|---|---|
| **Severity** | High |
| **Resource Type** | `AgentIdentity`, `AgentIdentityBlueprint` |
| **Required Permission** | `AgentIdentity.Read.All` |
| **Graph Endpoints** | `GET /servicePrincipals/{id}/owners`, `GET /servicePrincipals/{id}/sponsors`, `GET /applications/{id}/owners`, `GET /applications/{id}/sponsors` |
| **Frameworks** | CIS M365 v5 (5.3.1), NIST 800-53 (AC-6(5)) |

**What it detects:** Agent identities and blueprints that have zero owners **and** zero sponsors. The Entra Agent ID platform requires sponsors during blueprint creation, but they can be removed post-creation, leaving the agent orphaned.

**Detection logic:** Two loops — one over `context.agent_identities`, one over `context.agent_identity_blueprints`. For each resource, if both `owners` and `sponsors` are empty lists, emit a FAIL. Produces separate findings for agents and blueprints, each identifying the specific resource.

**Why sponsors matter:** Sponsors are a new concept introduced by the Agent ID platform. Unlike owners (who have management access), sponsors authorize the agent's lifecycle — they are the business justification for the agent's existence. An agent with no owners and no sponsors has no accountable party for:

- Permission reviews (who approves new permission requests?)
- Credential rotation (who rotates secrets/certificates?)
- Incident response (who is contacted when the agent behaves anomalously?)
- Decommissioning (who decides when the agent is no longer needed?)

**Risk:** Orphaned agents accumulate permissions and credentials without review, becoming attractive targets for credential abuse.

**Remediation:** Assign at least one owner and one sponsor. For agents: `POST /servicePrincipals/{id}/owners/$ref` and `POST /servicePrincipals/{id}/sponsors/$ref`. For blueprints: `POST /applications/{id}/sponsors/$ref`.

---

#### `entraid_agent_007` — Review external agent blueprint principals

| | |
|---|---|
| **Severity** | Medium |
| **Resource Type** | `AgentIdentityBlueprintPrincipal` |
| **Required Permission** | `AgentIdentity.Read.All` |
| **Graph Endpoints** | `GET /servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal` |
| **Frameworks** | NIST 800-53 (IA-8), CISA SCuBA (MS.AAD.8.1) |

**What it detects:** Agent blueprint principals where `appOwnerOrganizationId` differs from the current tenant ID. These represent agent blueprints published by external organizations (ISVs, partners, or Microsoft itself) that have been instantiated in your tenant.

**Detection logic:** For each blueprint principal, compares `bpp.app_owner_organization_id` against `context.tenant_id`. If both are set and they differ, emit a FAIL finding identifying the external organization ID and the blueprint name.

**Why this matters:** External blueprints operate with permissions granted in your tenant but are managed by an external organization. You cannot control the blueprint's code, update schedule, or security posture — you can only control the permissions you grant to it. This is analogous to third-party enterprise apps, but with the added risk that agents may operate autonomously.

**Risk:** External agents with broad permissions have limited visibility. You cannot audit the agent's internal behavior, only its Graph API calls. A compromised publisher could push malicious updates to the blueprint that affect all tenants using it.

**Remediation:** Review the external agent's publisher, permissions, and data access scope. Validate verified publisher status via the `verifiedPublisher` property. Remove or restrict untrusted agents. Consider using Conditional Access policies to limit external agent access.

---

#### `entraid_agent_008` — Ensure agent blueprints use federated credentials instead of client secrets

| | |
|---|---|
| **Severity** | Medium |
| **Resource Type** | `AgentIdentityBlueprint` |
| **Required Permission** | `AgentIdentity.Read.All` |
| **Graph Endpoints** | `GET /applications/microsoft.graph.agentIdentityBlueprint` |
| **Frameworks** | CIS M365 v5 (5.3.4), NIST 800-53 (IA-5) |

**What it detects:** Agent identity blueprints that use `passwordCredentials` (client secrets) for authentication without any `federatedIdentityCredentials` configured. Client secrets are shared secrets that can be leaked in code, logs, configuration files, or environment variables.

**Detection logic:** For each blueprint, if `len(bp.password_credentials) > 0` **and** `len(bp.federated_identity_credentials) == 0`, emit a FAIL. This means blueprints using both secrets and federated credentials pass — the check specifically flags secrets-only configurations.

**Why federated credentials are preferred:** Workload identity federation (federated identity credentials) eliminates shared secrets entirely. The agent authenticates using a token from an external identity provider (e.g., GitHub Actions OIDC, Azure Kubernetes Service, or another Entra ID tenant) that is exchanged for an Entra ID access token. No secret is ever stored or transmitted.

**Risk:** Client secrets can be exfiltrated through source code repositories, CI/CD logs, environment variable dumps, or insider access. Once leaked, the secret provides persistent access until rotated. Federated credentials eliminate this entire attack class.

**Remediation:** Replace client secrets with federated identity credentials or certificate-based key credentials. Remove the password credential via `POST /applications/{id}/removePassword`. Configure workload identity federation via `POST /applications/{id}/federatedIdentityCredentials`.

---

#### `entraid_agent_009` — Ensure stale agent identities are disabled or removed

| | |
|---|---|
| **Severity** | Medium |
| **Resource Type** | `AgentIdentity` |
| **Required Permission** | `AgentIdentity.Read.All` |
| **Graph Endpoints** | `GET /servicePrincipals/microsoft.graph.agentIdentity` |
| **Frameworks** | CIS M365 v5 (5.3.1), NIST 800-53 (AC-2(3)) |

**What it detects:** Enabled agent identities that were created more than 90 days ago but are still `accountEnabled: true`. These may be test agents, deprecated agents, or abandoned proof-of-concept identities that retain active permissions and credentials.

**Detection logic:** Constant `STALE_DAYS = 90`. For each agent, skips those that are disabled (`account_enabled == False`) or have no `created_date_time`. Parses the creation date and calculates age in days. If `age > 90` and `account_enabled == True`, emit a FAIL with the age.

**Limitation:** This check uses creation date as a proxy for activity because the `lastSignInDateTime` property is not currently available on the `agentIdentity` resource type. Future versions will correlate with `signInLogs` filtered by `servicePrincipalType eq 'ServiceIdentity'` for true last-activity detection.

**Risk:** Stale agents retain their permissions and credentials indefinitely. An attacker who discovers a forgotten agent's credentials gains persistent access to whatever permissions were granted — potentially months or years after the agent was last used.

**Remediation:** Disable or delete unused agent identities. Review sign-in logs (`GET /auditLogs/signIns?$filter=servicePrincipalId eq '{id}'`) to confirm inactivity before deletion. Use `PATCH /servicePrincipals/{id}` with `{"accountEnabled": false}` to disable.

---

#### `entraid_agent_010` — Ensure agent blueprints define inheritable permission restrictions

| | |
|---|---|
| **Severity** | Medium |
| **Resource Type** | `AgentIdentityBlueprint` |
| **Required Permission** | `AgentIdentity.Read.All` |
| **Graph Endpoints** | `GET /applications/microsoft.graph.agentIdentityBlueprint`, `GET /applications/{id}/inheritablePermissions` |
| **Frameworks** | NIST 800-53 (AC-6) |

**What it detects:** Blueprints where the `inheritablePermissions` collection is empty or unset. Without inheritable permission restrictions, there is no declared intent about which scopes agent instances should receive from the blueprint.

**Detection logic:** For each blueprint, if `not bp.inheritable_permissions` (empty list or falsy), emit a FAIL.

**InheritablePermissions explained:** The `inheritablePermissions` property on a blueprint defines how permissions are inherited by agent instances:

- **`enumeratedScopes`** — Only the explicitly listed scope GUIDs can be inherited. This is the recommended setting — it provides an allowlist of permissions.
- **`noScopes`** — Agent instances cannot inherit any permissions from the blueprint. They must be granted permissions independently.
- **`allAllowedScopes`** — Agent instances can inherit any permission (checked separately by `agent_002` at Critical severity).
- **Empty/unset** — No declaration. This is what `agent_010` flags — the absence of any stated policy.

**Risk:** Without `inheritablePermissions`, there is no documentation of the intended permission scope for agent instances. Admin reviewers cannot tell whether broad permissions are intentional or accidental. This creates governance friction and increases the risk of over-provisioning.

**Remediation:** Configure `inheritablePermissions` with `enumeratedScopes` and an explicit list of allowed scope GUIDs. Use `PATCH /applications/{blueprintId}` with the `inheritablePermissions` collection. If agent instances should not inherit any permissions, use `noScopes`.

---

#### `entraid_agent_011` — Ensure no agent identity is disabled by Microsoft

| | |
|---|---|
| **Severity** | Medium |
| **Resource Type** | `AgentIdentity` |
| **Required Permission** | `AgentIdentity.Read.All` |
| **Graph Endpoints** | `GET /servicePrincipals/microsoft.graph.agentIdentity` |
| **Frameworks** | NIST 800-53 (SI-4) |

**What it detects:** Agent identities where `disabledByMicrosoftStatus` is set to a value other than `null` or `"NotDisabled"`. Microsoft may disable agent identities for violations of the services agreement, abuse detection, or compromise indicators. The most common value is `"DisabledDueToViolationOfServicesAgreement"`.

**Detection logic:** For each agent, if `disabled_by_microsoft_status` is truthy **and** not equal to `"NotDisabled"`, emit a FAIL. The finding includes the specific status value in the title.

**Why this is Medium (not High):** The agent is already disabled — it cannot authenticate or access resources. The finding alerts you to investigate why it was disabled and whether other agents from the same blueprint may be at risk. It's an indicator, not an active threat.

**Risk:** A Microsoft-disabled agent may have been compromised, used for abuse, or violated platform policies. Other agents from the same blueprint (with the same code and configuration) may have similar issues. The disabled agent's credentials and permissions should also be reviewed.

**Remediation:** Investigate the disabled agent's activity via audit logs (`GET /auditLogs/directoryAudits?$filter=targetResources/any(t:t/id eq '{id}')`). Review sibling agents from the same blueprint (those sharing the same `agentIdentityBlueprintId`). Contact Microsoft support if the disabling was unexpected.

---

#### `entraid_agent_012` — Ensure agent identities and blueprints have descriptions

| | |
|---|---|
| **Severity** | Low |
| **Resource Type** | `AgentIdentityBlueprint`, `AgentIdentity` |
| **Required Permission** | `AgentIdentity.Read.All` |
| **Graph Endpoints** | `GET /applications/microsoft.graph.agentIdentityBlueprint`, `GET /servicePrincipals/microsoft.graph.agentIdentity` |
| **Frameworks** | NIST 800-53 (CM-8) |

**What it detects:** Two conditions:
1. **Blueprints** with no `description` **and** no meaningful `info` property (all URL fields are null)
2. **Agent identities** with no `displayName` or whose `displayName` equals their `id` (GUID used as name)

**Detection logic:** For blueprints, checks `not bp.description` and uses a helper `_has_meaningful_info()` that inspects the `info` dict — the Graph API returns `info` as `{"logoUrl": null, "marketingUrl": null, ...}` even when nothing is set, so the check verifies at least one value is non-null. For agents, checks if `display_name` is empty or equals the object `id`.

**Why this matters:** During incident response or permission reviews, administrators need to quickly understand what an agent does, who it's for, and how to contact the responsible team. Missing metadata creates friction that slows response time and increases the risk of incorrect remediation actions (e.g., disabling a critical production agent because its purpose was unclear).

**Risk:** Low — this is a governance hygiene finding, not a vulnerability. Missing descriptions do not directly enable attacks, but they degrade the organization's ability to manage and respond to agent-related incidents.

**Remediation:** For blueprints, add a description via `PATCH /applications/{id}` with `{"description": "..."}`. Include purpose, scope, and contact info in the `info` property. For agents, set a meaningful display name via `PATCH /servicePrincipals/{id}` with `{"displayName": "..."}`.

---

### Check Implementation Examples

**agent_001 — Agent with dangerous permissions:**

```python
class AgentDangerousPermissions(BaseCheck):
    """Detect agent identities holding permissions that should be blocked."""

    DANGEROUS_PERMS = {
        "Files.ReadWrite.All", "Files.Read.All",
        "Sites.FullControl.All", "Sites.ReadWrite.All", "Sites.Read.All",
        "User.ReadWrite.All", "User.DeleteRestore.All",
        "Directory.ReadWrite.All", "Group.ReadWrite.All",
        "RoleManagement.ReadWrite.Directory",
        "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All",
    }

    def execute(self, ctx: TenantContext) -> list[Finding]:
        findings = []

        for agent in ctx.agent_identities:
            app_role_assignments = ctx.get_agent_app_role_assignments(agent.id)
            granted = {a.resource_display_name + "/" + a.app_role_id
                       for a in app_role_assignments}
            # Resolve role IDs to permission names via resource SP lookup
            agent_perms = ctx.resolve_app_role_names(app_role_assignments)
            dangerous = agent_perms & self.DANGEROUS_PERMS
            if dangerous:
                findings.append(Finding(
                    check_id=self.metadata.check_id,
                    status=Status.FAIL,
                    severity=Severity.CRITICAL,
                    resource_type="agentIdentity",
                    resource_id=agent.id,
                    title=(
                        f"Agent '{agent.display_name}' holds "
                        f"dangerous permissions"
                    ),
                    description=(
                        f"Agent identity (servicePrincipalType: "
                        f"ServiceIdentity) holds permissions that "
                        f"Microsoft blocks for new agent grants: "
                        f"{', '.join(sorted(dangerous))}. This may "
                        f"indicate a legacy grant or platform bypass."
                    ),
                    remediation=(
                        "Remove the dangerous permissions via "
                        "DELETE /agentIdentities/{id}/appRoleAssignments"
                        "/{assignmentId}. Replace with least-privilege "
                        "scopes appropriate for the agent's function."
                    ),
                ))

        if not findings:
            findings.append(Finding(
                check_id=self.metadata.check_id,
                status=Status.PASS,
                title="No agent identities with dangerous permissions",
            ))
        return findings
```

**agent_006 — Agent with no owner or sponsor:**

```python
class AgentNoAccountability(BaseCheck):
    """Detect agent identities with no owners and no sponsors."""

    def execute(self, ctx: TenantContext) -> list[Finding]:
        findings = []

        for agent in ctx.agent_identities:
            owners = ctx.get_agent_owners(agent.id)
            sponsors = ctx.get_agent_sponsors(agent.id)
            if not owners and not sponsors:
                findings.append(Finding(
                    check_id=self.metadata.check_id,
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    resource_type="agentIdentity",
                    resource_id=agent.id,
                    title=(
                        f"Agent '{agent.display_name}' has no owner "
                        f"or sponsor"
                    ),
                    description=(
                        f"Agent identity has zero owners and zero "
                        f"sponsors. The Entra Agent ID platform "
                        f"requires sponsors during blueprint creation, "
                        f"but they may have been removed post-creation. "
                        f"No one is accountable for this agent's "
                        f"permissions and lifecycle."
                    ),
                    remediation=(
                        "Assign at least one owner and one sponsor to "
                        "the agent identity via POST /agentIdentities/"
                        "{id}/owners and POST /agentIdentities/{id}/"
                        "sponsors."
                    ),
                ))

        # Also check blueprints
        for bp in ctx.agent_identity_blueprints:
            owners = ctx.get_blueprint_owners(bp.id)
            sponsors = ctx.get_blueprint_sponsors(bp.id)
            if not owners and not sponsors:
                findings.append(Finding(
                    check_id=self.metadata.check_id,
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    resource_type="agentIdentityBlueprint",
                    resource_id=bp.id,
                    title=(
                        f"Blueprint '{bp.display_name}' has no owner "
                        f"or sponsor"
                    ),
                    description=(
                        f"Agent identity blueprint has zero owners and "
                        f"zero sponsors. All agent identities created "
                        f"from this blueprint lack accountability."
                    ),
                    remediation=(
                        "Assign at least one sponsor to the blueprint "
                        "via POST /agentIdentityBlueprints/{id}/sponsors."
                    ),
                ))

        if not findings:
            findings.append(Finding(
                check_id=self.metadata.check_id,
                status=Status.PASS,
                title=(
                    "All agent identities and blueprints have "
                    "owners or sponsors"
                ),
            ))
        return findings
```

### Updated Check Distribution

With the agent category, the total check count increases to 82:

| Category | Critical | High | Medium | Low | Total |
|----------|----------|------|--------|-----|-------|
| Conditional Access | 3 | 5 | 3 | 0 | **13** |
| Authentication | 1 | 1 | 4 | 2 | **8** |
| Privileged Roles | 4 | 3 | 1 | 0 | **10** |
| Applications | 3 | 5 | 4 | 0 | **12** |
| Service Principals | 0 | 5 | 4 | 0 | **9** |
| Users & Guests | 1 | 2 | 3 | 1 | **7** |
| Organization | 0 | 2 | 3 | 0 | **5** |
| Cross-Tenant & B2B | 0 | 2 | 3 | 0 | **5** |
| **Agentic Identity** | **2** | **4** | **5** | **1** | **12** |
| **Total** | **14** | **29** | **30** | **4** | **81** |

### Framework Mappings

Agent checks map to existing and emerging compliance frameworks:

| Framework | Relevant Controls | Agent Check Coverage |
|---|---|---|
| **CIS Microsoft 365 v5** | 5.1.5.1 (app consent), 5.3.1 (app permissions review) | agent_003, agent_004, agent_005, agent_007 |
| **CISA SCuBA** | MS.AAD.6.1 (apps with high-priv), MS.AAD.8.1 (guest access) | agent_001, agent_002, agent_010 |
| **NIST 800-53** | AC-6 (least privilege), AC-17 (remote access), IA-8 (non-org users) | agent_001–agent_011 |
| **Microsoft Entra Agent ID Governance** | Blueprint sponsor requirements, inheritable permission controls, blocked permission enforcement | agent_002, agent_003, agent_005, agent_006 |

### Data Collection Additions

Agent discovery adds dedicated data collection to the scan pipeline using the GA Agent Identity endpoints:

| Order | Endpoint | Purpose | Dependencies |
|---|---|---|---|
| 16 | `GET /agentIdentityBlueprints` | All agent blueprints (templates) | None |
| 17 | `GET /agentIdentityBlueprintPrincipals` | All blueprint principals in the tenant | None |
| 18 | `GET /agentIdentities` | All agent identity instances | None |
| 19 | `GET /agentIdentityBlueprints/{id}/inheritablePermissions` (per blueprint) | Inheritable permission configuration | Order 16 |
| 20 | `GET /agentIdentities/{id}/appRoleAssignments` (per agent) | Application permissions per agent | Order 18 |
| 21 | `GET /agentIdentities/{id}/owners` + `/sponsors` (per agent) | Accountability metadata | Order 18 |
| 22 | `GET /agentIdentityBlueprintPrincipals/{id}/owners` + `/sponsors` (per BP principal) | Blueprint accountability | Order 17 |

All agent data is stored in `TenantContext.agent_identities`, `TenantContext.agent_identity_blueprints`, and `TenantContext.agent_identity_blueprint_principals` for downstream checks to consume. The data is fetched in parallel where possible (Orders 16–18 have no dependencies on each other).

**Required permissions:** `AgentIdentity.Read.All` (application) to read agent identities, blueprints, and blueprint principals. This is a read-only permission and does not grant the ability to create or modify agent identities.

### Limitations and Future Roadmap

**Current limitations:**

- **Agent registry (beta).** The `agentRegistry` endpoints (agent card manifests, instances, collections) are in beta and may change. EntraLint uses only GA v1.0 endpoints for agent identity checks. Agent registry data will be integrated when the endpoints reach GA.
- **Delegation chain visibility.** Agent-to-agent calls (A calls B with on-behalf-of tokens) are not visible via Graph API configuration data. Detecting these requires runtime audit log analysis, which is out of scope for the current static configuration scanner.
- **Identity Protection signals.** The `agentRiskDetection` and `riskyAgent` resource types (beta) provide runtime risk signals for agents. EntraLint will integrate these when they reach GA to flag agents with active risk detections.
- **Copilot Studio internals.** Power Platform environment-level agent policies (DLP, connector restrictions) are not accessible via Microsoft Graph. EntraLint scans what's visible at the Entra ID layer; Power Platform governance is a separate concern.

**Planned roadmap:**

| Phase | Scope |
|---|---|
| **v0.2** (initial) | Ship agent_001–agent_006 using GA Agent Identity APIs (`/agentIdentities`, `/agentIdentityBlueprints`) |
| **v0.3** | Add agent_007–agent_012, integrate `agentRegistry` beta endpoints for card manifest analysis |
| **v0.4** | Audit log correlation — detect agent sign-in patterns from `signInLogs` filtered by `servicePrincipalType eq 'ServiceIdentity'`, integrate `riskyAgent` and `agentRiskDetection` signals |
| **v1.0** | Full agent governance: Conditional Access policy validation for agents, inheritable permission drift detection, sponsor lifecycle compliance |

---

## GitHub Repository Structure

```
entralint/
├── .github/
│   ├── workflows/
│   │   ├── ci.yaml              # pytest, mypy, ruff on every PR
│   │   ├── release.yaml         # PyPI publish on tag
│   │   └── self-scan.yaml       # EntraLint scanning its own test tenant
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   ├── new_check_request.md
│   │   └── feature_request.md
│   └── CODEOWNERS
├── src/
│   └── entralint/
│       ├── __init__.py
│       ├── __main__.py          # Entry point: python -m entralint
│       ├── cli/
│       │   ├── __init__.py
│       │   ├── app.py           # Typer app definition
│       │   ├── commands/
│       │   │   ├── scan.py
│       │   │   ├── login.py
│       │   │   ├── config.py
│       │   │   ├── cache.py     # Cache management commands
│       │   │   └── report.py
│       │   └── output.py        # Rich console formatters
│       ├── core/
│       │   ├── __init__.py
│       │   ├── check.py         # BaseCheck, Finding, Severity, Status
│       │   ├── engine.py        # Check discovery, dependency DAG, execution pipeline
│       │   ├── models.py        # Pydantic models for Graph API responses
│       │   ├── context.py       # TenantContext with cached API data
│       │   └── errors.py        # Error taxonomy: SkippedLicense, SkippedPermission, etc.
│       ├── auth/
│       │   ├── __init__.py
│       │   ├── provider.py      # AuthProvider (MSAL wrapper)
│       │   ├── auth_code.py     # Authorization code + PKCE (default)
│       │   ├── device_code.py   # Device code (fallback)
│       │   ├── client_credentials.py
│       │   └── managed_identity.py
│       ├── graph/
│       │   ├── __init__.py
│       │   ├── client.py        # Graph API client with retry/throttle/token refresh
│       │   ├── endpoints.py     # Endpoint constants and builders
│       │   ├── pagination.py    # Auto-pagination handler
│       │   ├── cache.py         # SQLite-backed response cache
│       │   ├── batch.py         # $batch request builder
│       │   └── sign_in_activity.py  # Dedicated signInActivity fetcher
│       ├── checks/
│       │   ├── __init__.py
│       │   ├── conditional_access/
│       │   │   ├── ca_mfa_required_all_users/
│       │   │   │   ├── ca_mfa_required_all_users.py
│       │   │   │   └── ca_mfa_required_all_users.metadata.json
│       │   │   ├── ca_block_legacy_auth/
│       │   │   └── ... (13 CA checks)
│       │   ├── mfa/              # 10 MFA checks
│       │   ├── privileged_roles/ # 10 privilege checks
│       │   ├── applications/     # 12 app security checks
│       │   ├── guests/           # 7 guest checks
│       │   ├── stale_accounts/   # 5 stale account checks
│       │   ├── auth_policies/    # 8 auth policy checks
│       │   └── cross_tenant/     # 5 cross-tenant checks
│       ├── frameworks/
│       │   ├── cis_m365_v5.json
│       │   ├── cisa_scuba.json
│       │   └── nist_800_53.json
│       ├── reports/
│       │   ├── __init__.py
│       │   ├── html.py          # Standalone HTML generator
│       │   ├── json_report.py
│       │   ├── sarif.py
│       │   ├── csv_report.py
│       │   ├── markdown.py
│       │   ├── pdf.py           # Playwright-based PDF generation
│       │   └── templates/
│       │       ├── report.html.j2
│       │       ├── dashboard.html.j2
│       │       └── static/      # Embedded CSS, JS, Chart.js
│       ├── multi_tenant/
│       │   ├── __init__.py
│       │   ├── config.py        # YAML config loader with secret validation
│       │   ├── manager.py       # TenantManager (async)
│       │   └── aggregator.py    # Cross-tenant report aggregation
│       ├── validation/
│       │   ├── __init__.py
│       │   ├── permissions.py   # Pre-scan permission validator
│       │   └── license.py       # Tenant license detector
│       └── web/                  # Optional web dashboard
│           ├── __init__.py
│           ├── app.py           # FastAPI application
│           ├── routes/
│           ├── templates/       # Jinja2 + HTMX templates
│           └── static/
├── tests/
│   ├── unit/
│   │   ├── checks/             # Unit tests per check
│   │   ├── core/
│   │   ├── auth/
│   │   ├── graph/              # Cache, batch, rate limiting tests
│   │   └── validation/         # Permission and license validation tests
│   ├── integration/
│   │   └── test_graph_client.py
│   └── fixtures/
│       └── mock_graph_responses/ # Recorded API responses
├── docs/
│   ├── getting-started.md
│   ├── checks-reference.md      # Auto-generated from metadata
│   ├── custom-checks.md
│   ├── multi-tenant.md
│   └── ci-cd-integration.md
├── pyproject.toml               # uv project config
├── uv.lock                      # Locked dependencies
├── README.md                    # Hero README with badges, quickstart
├── CONTRIBUTING.md
├── LICENSE                      # AGPL 3.0
├── SECURITY.md
└── Dockerfile
```

### Key structural differences from original design

| Addition | Purpose |
|----------|---------|
| `auth/auth_code.py` | Default interactive auth (PKCE), replacing device code as primary |
| `graph/cache.py` | SQLite-backed API response cache |
| `graph/batch.py` | `$batch` request builder for signInActivity |
| `graph/sign_in_activity.py` | Dedicated rate-limited signInActivity fetcher |
| `core/errors.py` | Error taxonomy types |
| `validation/permissions.py` | Pre-scan permission introspection |
| `validation/license.py` | Tenant license detection |
| `cli/commands/cache.py` | Cache management CLI commands |
| `reports/pdf.py` | Playwright-based PDF generation |
| `uv.lock` | uv lockfile (replacing Poetry) |

---

## Testing Strategy

### Unit tests

Every check gets a unit test with mock Graph API responses. Test fixtures are recorded API responses stored in `tests/fixtures/mock_graph_responses/`:

```python
# tests/unit/checks/test_ca_mfa_required_all_users.py
def test_fails_when_no_mfa_policy(mock_tenant_context):
    mock_tenant_context.conditional_access_policies = []
    check = CaMfaRequiredAllUsers()
    findings = check.execute(mock_tenant_context)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL
    assert findings[0].severity == Severity.CRITICAL

def test_passes_when_mfa_policy_exists(mock_tenant_context):
    mock_tenant_context.conditional_access_policies = [VALID_MFA_POLICY]
    check = CaMfaRequiredAllUsers()
    findings = check.execute(mock_tenant_context)
    assert findings[0].status == Status.PASS
```

### Integration tests

Integration tests run against a dedicated test Entra tenant (configured in CI secrets). These validate:

- Authentication flows work end-to-end
- Graph API pagination handles real response formats
- Rate limiting and retry logic functions correctly
- Cache invalidation works with real API responses

### Config validation tests

Dedicated tests ensure the config parser rejects inline secrets:

```python
def test_rejects_inline_client_secret():
    config = {"client_secret": "some-secret-value", "tenant_id": "..."}
    with pytest.raises(ConfigSecurityError, match="Inline 'client_secret' is not allowed"):
        ConfigValidator().validate_tenant(config)

def test_accepts_env_var_reference():
    config = {"client_secret_env": "MY_SECRET_VAR", "tenant_id": "..."}
    ConfigValidator().validate_tenant(config)  # Should not raise
```

### CI pipeline

The `ci.yaml` workflow runs on every PR:

```yaml
- pytest (unit + integration)
- mypy --strict
- ruff check + ruff format --check
- entralint self-scan (dogfooding against test tenant)
```



