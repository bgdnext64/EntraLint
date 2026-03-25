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
16. [GitHub Repository Structure](#github-repository-structure)
17. [Testing Strategy](#testing-strategy)

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

```yaml
# GitHub Actions example
- name: EntraLint Security Scan
  env:
    ENTRALINT_TENANT_ID: ${{ secrets.TENANT_ID }}
    ENTRALINT_CLIENT_ID: ${{ secrets.CLIENT_ID }}
    ENTRALINT_CLIENT_CERTIFICATE_PATH: ${{ secrets.CERT_PATH }}
  run: entralint scan --output sarif --output-file results.sarif
```

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



