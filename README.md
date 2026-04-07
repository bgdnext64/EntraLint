# EntraLint

**Lint your Entra ID. Fix before they breach.**

EntraLint is an open-source, CLI-first security linter for [Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/fundamentals/whatis) (formerly Azure Active Directory). Think of it as ESLint or Ruff, but for your identity configuration instead of your code — it reads your tenant settings, checks them against security best practices and compliance benchmarks, and tells you exactly what to fix.

## Why EntraLint?

Identity misconfigurations are one of the most common root causes of cloud breaches. Microsoft Entra ID controls who can access what in your organization — your users, apps, service principals, conditional access policies, privileged roles, and now AI agent identities. A single misconfiguration (no MFA requirement, over-privileged service principal, stale admin account) can be all an attacker needs.

The problem is that Entra ID has hundreds of security-relevant settings spread across dozens of admin blades. Keeping track of them manually doesn't scale, especially across multiple tenants. EntraLint automates this:

- **Finds misconfigurations automatically** — 82 checks cover conditional access, MFA, privileged roles, app registrations, service principals, guest accounts, organization settings, cross-tenant access, and AI agent identities
- **Maps to compliance frameworks** — Every finding references CIS Microsoft 365 Foundations Benchmark v5, CISA SCuBA (BOD 25-01), and/or NIST 800-53 controls
- **Fits into your workflow** — Run it locally during development, in CI/CD pipelines via SARIF output, or as a scheduled audit tool
- **Requires read-only access** — EntraLint never modifies your tenant. It only reads configuration data through the Microsoft Graph API

## Quick Start

EntraLint requires Python 3.11+ and [uv](https://docs.astral.sh/uv/) (a fast Python package manager).

```bash
# 1. Clone the repository
git clone https://github.com/bgdnext64/EntraLint.git
cd EntraLint

# 2. Install dependencies
uv sync

# 3. Authenticate to your tenant
uv run entralint login

# 4. Run a security scan
uv run entralint scan
```

That's it. EntraLint authenticates via device-code flow (you'll see a URL and code to enter in your browser), scans your tenant's configuration through the Microsoft Graph API, and prints the results directly in your terminal.

### What You'll See

EntraLint prints color-coded findings as each check runs:

```
╭─ EntraLint v0.1.0 ──────────────────────────────────────────╮
│ Tenant: contoso.onmicrosoft.com                              │
│ Checks: 82 | Framework: All                                  │
╰──────────────────────────────────────────────────────────────╯

Collecting data from Microsoft Graph API...
  ✓ Organization settings
  ✓ Conditional Access policies
  ✓ Users (3,847)
  ✓ Applications (142)
  ✓ Service Principals (891)
  ✓ Role Assignments
  ✓ Agent Identities

Running security checks...

 CRITICAL  entraid_ca_001   No CA policy requires MFA for all users
 CRITICAL  entraid_priv_002 6 permanent Global Admin assignments (max: 4)
 HIGH      entraid_app_001  12 apps with secrets expiring within 30 days
 PASS      entraid_ca_002   Legacy authentication blocked
 PASS      entraid_auth_001 Security defaults disabled (CA in use)

╭─ Summary ────────────────────────────────────────────────────╮
│  Passed: 48  Failed: 17  Skipped: 5                          │
╰──────────────────────────────────────────────────────────────╯
```

### Saving Reports

Generate reports in multiple formats for sharing, archival, or CI/CD integration:

```bash
# Self-contained HTML report (great for sharing with your team)
uv run entralint scan -f html --output-file report.html

# JSON for programmatic consumption
uv run entralint scan -f json --output-file results.json

# SARIF for GitHub Code Scanning integration
uv run entralint scan -f sarif --output-file results.sarif
```

## Security Checks (82)

EntraLint ships with 82 built-in checks organized into 9 categories:

| Category | Count | Severities | What It Covers |
|---|---|---|---|
| Conditional Access | 14 | 3 Critical, 5 High, 3 Medium | MFA enforcement, legacy auth blocking, device compliance, sign-in/user risk policies, device code flow |
| Authentication | 10 | 1 Critical, 1 High, 4 Medium, 2 Low | Password protection, banned passwords, SSPR, FIDO2, Authenticator number matching, TAP lifetime |
| Privileged Roles | 10 | 4 Critical, 3 High, 1 Medium | PIM usage, Global Admin count, standing assignments, activation approval, emergency access accounts |
| Applications | 9 | 3 Critical, 5 High, 4 Medium | Expired/long-lived secrets, excessive Graph permissions, no owners, unrestricted user consent |
| Service Principals | 9 | — High, Medium | Expired credentials, high-privilege grants, dual credential types, stale SPs |
| Users & Guests | 9 | 1 Critical, 2 High, 3 Medium, 1 Low | Stale accounts, guest access level, MFA registration, disabled users with roles |
| Organization | 9 | — High, Medium | Security defaults, verified domains, cross-tenant trust settings |
| Agentic Identity | 12 | 2 Critical, 4 High, 5 Medium, 1 Low | AI agent permissions, blueprint scope inheritance, blocked permission enforcement, orphaned agents, stale agents |

Every check includes:

- A severity level (Critical, High, Medium, Low)
- Compliance framework mappings (CIS, CISA SCuBA, NIST 800-53)
- A description of the risk
- Remediation guidance with links to Microsoft documentation

### Agentic Identity Checks

EntraLint is the first security scanner to provide dedicated checks for **Microsoft Entra Agent ID** — the GA platform (shipped March 2026) that gives AI agents their own first-class identity type in Entra ID. These 12 checks cover agent blueprints, blueprint principals, and agent identity instances, detecting issues like:

- Agents holding dangerous or blocked permissions (e.g., `Files.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`)
- Blueprints using `allAllowedScopes` inheritance (allows agents to inherit any permission)
- Orphaned agents with no owner or sponsor
- Stale agent identities with valid credentials
- External (third-party) agent blueprints operating in your tenant
- Agents using client secrets instead of federated credentials

## CLI Reference

### Commands

| Command | Description |
|---|---|
| `login` | Authenticate to your Entra ID tenant |
| `scan` | Scan your tenant for security misconfigurations |
| `list-checks` | Browse available checks (filter by `--category`, `--severity`) |
| `show-check <ID>` | View full details for a specific check |
| `explain <ID>` | Alias for `show-check` |
| `list-frameworks` | List supported compliance frameworks |
| `cache` | Manage the local data cache (`--status`, `--clear`) |
| `report` | Generate reports from cached scan data |
| `permissions` | Show required permissions and generate grant scripts |
| `config` | Manage configuration |
| `version` | Show version |

### Scan Options

```bash
uv run entralint scan [OPTIONS]
```

| Option | Description |
|---|---|
| `--tenant TEXT` | Tenant ID or domain to scan |
| `--format/-f TEXT` | Output format: `table` (default), `json`, `sarif`, `html` |
| `--output-file PATH` | Write report to a file |
| `--fail-on TEXT` | Exit non-zero at a severity threshold: `critical`, `high`, `medium`, `low` |
| `--checks TEXT` | Run only specific check IDs (comma-separated) |
| `--category TEXT` | Filter checks by category |
| `--severity TEXT` | Filter checks by severity |
| `--no-cache` | Bypass the local data cache (fetch everything fresh) |
| `--offline` | Run checks against cached data only — no API calls |
| `--config PATH` | Path to `.entralint.yaml` config file |
| `--baseline PATH` | Compare results against a baseline file |
| `--update-baseline` | Save current scan as the new baseline |
| `--fail-on-new` | Exit non-zero only for new findings vs. baseline |
| `--quiet/-q` | Suppress console output (CI mode) |
| `--verbose/-v` | Verbose output |

### Common Workflows

**Filter by severity** — only show Critical and High findings:

```bash
uv run entralint scan --severity critical,high
```

**CI/CD gate** — fail the pipeline if any Critical findings exist:

```bash
uv run entralint scan --fail-on critical --quiet -f sarif --output-file results.sarif
```

**Offline iteration** — scan once to populate the cache, then iterate locally:

```bash
uv run entralint scan                    # populates cache
uv run entralint scan --offline          # instant re-scan, no API calls
```

**Baseline drift detection** — track changes between scans:

```bash
uv run entralint scan --update-baseline  # save current state
# ... time passes, config changes ...
uv run entralint scan --baseline .entralint-baseline.json --fail-on-new
```

**Inspect a specific check** — see what it does and how to fix it:

```bash
uv run entralint explain entraid_ca_001
```

**Grant permissions** — generate a script to grant all required Graph API permissions:

```bash
uv run entralint permissions -f powershell --client-id YOUR_APP_ID
```

## GitHub Action

EntraLint ships as a GitHub Action. Add it to any workflow to scan your tenant on a schedule or on every push and see results in GitHub Code Scanning.

### Quick Setup

**Option A: Client secret** — simplest, uses a secret stored in GitHub:

```yaml
name: EntraLint Security Scan

on:
  schedule:
    - cron: "0 6 * * 1"  # Every Monday at 6 AM UTC
  workflow_dispatch:

permissions:
  security-events: write
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run EntraLint
        uses: bgdnext64/EntraLint@main
        with:
          tenant-id: ${{ secrets.ENTRALINT_TENANT_ID }}
          client-id: ${{ secrets.ENTRALINT_CLIENT_ID }}
          client-secret: ${{ secrets.ENTRALINT_CLIENT_SECRET }}
          fail-on: high
```

**Option B: Workload identity federation** — no secrets stored in GitHub, uses OIDC:

```yaml
name: EntraLint Security Scan

on:
  schedule:
    - cron: "0 6 * * 1"
  workflow_dispatch:

permissions:
  security-events: write
  contents: read
  id-token: write          # Required for OIDC token exchange

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Azure Login (OIDC)
        uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

      - name: Run EntraLint
        uses: bgdnext64/EntraLint@main
        with:
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          use-default-credential: "true"
          fail-on: high
```

### Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `tenant-id` | Yes | — | Entra ID tenant ID or domain |
| `client-id` | No | — | App registration client ID (not needed with `use-default-credential`) |
| `client-secret` | No | — | Client secret for app-only auth |
| `client-certificate-path` | No | — | Path to PEM certificate file |
| `use-default-credential` | No | `false` | Use DefaultAzureCredential (WIF, managed identity, az CLI) |
| `fail-on` | No | `medium` | Severity threshold for non-zero exit |
| `severity` | No | — | Only report findings at/above this severity |
| `checks` | No | — | Comma-separated check IDs to run |
| `category` | No | — | Only run checks in this category |
| `config` | No | — | Path to `.entralint.yaml` |
| `baseline` | No | — | Path to baseline file for drift detection |
| `fail-on-new` | No | `false` | Only fail on NEW findings vs baseline |
| `update-baseline` | No | `false` | Save scan as new baseline |
| `upload-sarif` | No | `true` | Upload SARIF to GitHub Code Scanning |

### Outputs

| Output | Description |
|---|---|
| `sarif-file` | Path to the generated SARIF report |
| `findings-count` | Total number of findings |
| `critical-count` | Number of critical findings |
| `high-count` | Number of high/critical findings |
| `exit-code` | Scan exit code (0 = pass) |

### Secrets Setup

**For client secret auth (Option A):**

1. Register an app in Entra ID with application permissions (see [Permissions](#permissions))
2. Create a client secret
3. Add these repository secrets:
   - `ENTRALINT_TENANT_ID` — Your tenant ID
   - `ENTRALINT_CLIENT_ID` — The app registration client ID
   - `ENTRALINT_CLIENT_SECRET` — The client secret
4. Grant admin consent for the required permissions:
   ```bash
   uv run entralint permissions -f powershell --client-id YOUR_APP_ID
   ```

**For workload identity federation (Option B):**

1. Register an app in Entra ID with application permissions
2. Add a federated credential: **Settings → Certificates & secrets → Federated credentials → Add credential → GitHub Actions**
   - Organization: your GitHub org/username
   - Repository: your repo name
   - Entity type: Branch, Tag, Pull Request, or Environment
3. Add these repository secrets:
   - `AZURE_TENANT_ID` — Your tenant ID
   - `AZURE_CLIENT_ID` — The app registration client ID
   - `AZURE_SUBSCRIPTION_ID` — Any Azure subscription ID (required by `azure/login`)
4. Grant admin consent for the required permissions

### CI/CD Environment Variables

For non-GitHub CI systems (Azure DevOps, GitLab, Jenkins), set these environment variables:

```bash
# Option A: Client secret
export ENTRALINT_TENANT_ID="your-tenant-id"
export ENTRALINT_CLIENT_ID="your-client-id"
export ENTRALINT_CLIENT_SECRET="your-client-secret"
entralint scan --fail-on critical --quiet -f sarif --output-file results.sarif

# Option B: DefaultAzureCredential (WIF, managed identity, az login)
export ENTRALINT_TENANT_ID="your-tenant-id"
export ENTRALINT_USE_DEFAULT_CREDENTIAL=true
entralint scan --fail-on critical --quiet -f sarif --output-file results.sarif
```

The scan command auto-detects the authentication method:
1. **Workload identity federation** — if `AZURE_FEDERATED_TOKEN_FILE` is present (set by `azure/login`)
2. **Managed identity** — if `IDENTITY_ENDPOINT` is present (Azure-hosted)
3. **Explicit opt-in** — if `ENTRALINT_USE_DEFAULT_CREDENTIAL=true`
4. **Client credentials** — if `ENTRALINT_CLIENT_SECRET` or `ENTRALINT_CLIENT_CERTIFICATE_PATH` is set
5. **Cached token** — falls back to `entralint login` cached token

## Configuration

Create a `.entralint.yaml` file in your project root to customize behavior:

```yaml
# Suppress a check with a documented reason
suppress:
  - check_id: ca_003
    reason: "Legacy VPN exception approved by CISO — ticket SEC-1234"

# Override severity for a check
overrides:
  ca_001:
    severity: critical

# Exclude checks entirely
exclude_checks:
  - org_001

# CI/CD: fail at this severity threshold
fail_on: high

# Baseline file for drift detection
baseline: .entralint-baseline.json

# Additional directories for custom checks
custom_checks_dirs:
  - ./my-checks
```

## Custom Checks

You can extend EntraLint with your own checks. Create a Python file in `~/.entralint/custom_checks/` or a local `.entralint/checks/` directory — EntraLint auto-discovers them alongside the built-in checks.

```python
from entralint.core.models import CheckMetadata, Finding, Severity, Status
from entralint.core.registry import BaseCheck, check

@check
class MyCustomCheck(BaseCheck):
    metadata = CheckMetadata(
        check_id="custom_001",
        title="My Custom Check",
        category="organization",
        severity=Severity.MEDIUM,
        description="Checks for a custom condition",
        remediation="Fix the condition",
        frameworks=["Internal Policy"],
    )

    def execute(self, ctx) -> list[Finding]:
        # Access tenant data via ctx (TenantContext)
        # Return PASS or FAIL findings
        return [Finding(status=Status.PASS, title="All good")]
```

## Permissions

EntraLint needs **read-only** access to your Entra ID tenant. It authenticates through the Microsoft Graph API and requires these permissions:

| Permission | What It Reads |
|---|---|
| `Directory.Read.All` | Users, groups, service principals, org config |
| `Policy.Read.All` | Conditional Access policies, auth methods, authorization policy |
| `Application.Read.All` | App registrations, credentials |
| `RoleManagement.Read.Directory` | Directory role assignments |
| `AuditLog.Read.All` | Sign-in logs (requires Entra ID P1+) |
| `AgentIdentity.Read.All` | Agent identities, blueprints, blueprint principals |

Use the built-in `permissions` command to see exactly what's needed and generate a ready-to-run grant script:

```bash
# Show all required permissions in a table
uv run entralint permissions

# Generate a PowerShell script to grant everything
uv run entralint permissions -f powershell --client-id YOUR_APP_ID

# Generate an Azure CLI script instead
uv run entralint permissions -f azcli --client-id YOUR_APP_ID
```

Some checks require Entra ID P1 or P2 licenses (sign-in logs, Identity Protection). If your tenant doesn't have the required license, those checks are gracefully skipped with an informational message — the rest of the scan runs normally.

## Development

```bash
# Clone and install
git clone https://github.com/bgdnext64/EntraLint.git
cd EntraLint
uv sync

# Run the CLI
uv run entralint version

# Run the test suite (432 tests)
uv run pytest

# Lint
uv run ruff check src/ tests/

# Type check
uv run mypy
```

### Project Structure

```
src/entralint/
├── cli/          # Typer CLI commands and Rich output formatting
├── core/         # Check engine, Pydantic models, TenantContext
├── auth/         # MSAL authentication (device code, client credentials)
├── graph/        # Graph API client, caching, pagination, rate limiting
├── checks/       # 82 built-in security checks (auto-discovered)
│   ├── conditional_access/
│   ├── authentication/
│   ├── privileged_roles/
│   ├── applications/
│   ├── service_principals/
│   ├── users/
│   ├── organization/
│   └── agent_identity/
├── reports/      # Output formatters (HTML, JSON, SARIF)
└── frameworks/   # Compliance framework mappings
```

## License

AGPL-3.0 — See [LICENSE](LICENSE) for details.
