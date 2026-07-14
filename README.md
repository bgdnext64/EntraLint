# EntraLint

**Lint your Entra ID. Fix before they breach.**

> **Disclaimer:** EntraLint is an independent, community-driven open-source project created by Brian Davis. It is **not** affiliated with, endorsed by, or sponsored by Microsoft. "Entra" and "Azure" are trademarks of Microsoft Corporation.

EntraLint is an open-source, CLI-first security linter for [Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/fundamentals/whatis) (formerly Azure Active Directory). Think of it as ESLint or Ruff, but for your identity configuration instead of your code. It reads your tenant settings, checks them against security best practices and compliance benchmarks, and tells you exactly what to fix.

## Why EntraLint?

Identity misconfigurations are one of the most common root causes of cloud breaches. Microsoft Entra ID controls who can access what in your organization — your users, apps, service principals, conditional access policies, privileged roles, and now AI agent identities. A single misconfiguration (no MFA requirement, over-privileged service principal, stale admin account) can be all an attacker needs.

Microsoft provides powerful built-in tools like Identity Secure Score and Entra Recommendations to track your tenant's security posture. EntraLint extends that coverage into your engineering workflow — adding CI/CD integration, deeper checks across applications and service principals, compliance framework mappings, and coverage for the newest Entra ID surfaces:

- **Finds misconfigurations automatically** — 88 checks cover conditional access, MFA, privileged roles, app registrations, service principals, guest accounts, organization settings, cross-tenant access, and AI agent identities
- **Maps to compliance frameworks** — Every finding references CIS Microsoft 365 Foundations Benchmark v5, CISA SCuBA (BOD 25-01), and/or NIST 800-53 controls
- **Fits into your workflow** — Run it locally during development, in CI/CD pipelines via SARIF output, or as a scheduled audit tool
- **Requires read-only access** — EntraLint never modifies your tenant. It only reads configuration data through the Microsoft Graph API

## Why Not Just Use Secure Score?

It's a fair question. Microsoft ships excellent built-in tools — Identity Secure Score, Entra Recommendations, and Defender for Identity — and you should absolutely use them. EntraLint is designed to complement those tools, not replace them. Here's how the coverage compares:

| Capability | Identity Secure Score | Entra Recommendations | Defender for Identity | EntraLint |
|---|---|---|---|---|
| **Where it runs** | Azure portal dashboard | Azure portal dashboard | Requires sensor on DCs / Entra Connect | CLI, CI/CD pipelines, GitHub Actions |
| **Focus area** | ~20 high-level Entra ID settings | ~50 Entra ID + hybrid recommendations | On-premises AD, Kerberos, NTLM, certificates | Cloud-native Entra ID configuration (88 checks) |
| **App & SP credential hygiene** | — | Expiring creds only | — | 18 checks: expired, long-lived, dual-type, high-privilege grants, orphaned owners, stale SPs |
| **Conditional Access depth** | MFA, legacy auth, risk policies | Same as Secure Score | — | 14 checks: device code flow, session controls, exclusion sprawl, guest targeting, device compliance for admins |
| **Privileged role analysis** | GA count, least privilege | Same | Lateral movement paths (on-prem) | 10 checks: PIM usage, break-glass accounts, guests in roles, SPs in roles, multi-role users, per-role caps |
| **Agentic identity (Entra Agent ID)** | — | — | — | 18 dedicated checks (first scanner to cover this) |
| **Cross-tenant & guest access** | — | — | — | 8 checks: inbound/outbound trust, MFA trust, guest invite settings, guest CA coverage |
| **Output formats** | Portal only | Portal only | Portal / Sentinel | Table, JSON, SARIF, HTML |
| **CI/CD gating** | No | No | No | `--fail-on critical` exits non-zero |
| **Baseline drift detection** | No | No | No | `--baseline` + `--fail-on-new` |
| **Compliance mapping** | — | — | — | CIS M365 v5, CISA SCuBA, NIST 800-53 per check |
| **Custom checks** | No | No | No | Drop a `.py` file, auto-discovered |
| **Cost** | Free (portal) | Free / P1 for some | Requires Defender for Identity license | Free, open-source (AGPL-3.0) |

### What overlaps and what doesn't

Microsoft's built-in tools and EntraLint are largely complementary — there's minimal redundancy. 13 of EntraLint's 88 checks overlap with what Secure Score and Entra Recommendations already cover, while the remaining **75 checks extend into areas** those tools weren't designed to address (CI/CD-oriented linting, deep app/SP credential analysis, cross-tenant trust, and agentic identity).

| Coverage source | Overlapping checks | What's covered |
|---|---|---|
| **Identity Secure Score** | 8 checks | MFA for all users, MFA for admins, block legacy auth, sign-in risk policy, user risk policy, restrict user consent, SSPR, Global Admin count |
| **Entra Recommendations** | 5 additional | Expiring app credentials, unused app credentials, expiring SP credentials, stale user accounts, least-privilege roles |
| **Defender for Identity** | 0 | Defender for Identity excels at on-premises AD security — EntraLint focuses on the cloud-native Entra ID configuration surface |
| **Unique to EntraLint** | **75 checks** | Device code flow blocking, persistent browser sessions, named location review, CA exclusion sprawl, guest CA targeting, sign-in frequency for admins, FIDO2/passwordless, banned password lists, number matching, TAP lifetime, certificate-based auth, break-glass accounts, guests/SPs in privileged roles, per-role assignment caps, multi-role detection, app secret lifetime, non-admin app owners with high-priv permissions, excessive delegated permissions, multi-tenant app review, disabled SPs with credentials, third-party SP permissions, broad delegated grants, dual credential types, cross-tenant trust settings, guest invitation restrictions, app registration restrictions, all 18 agentic identity checks |

### When to use what

**Use Secure Score / Entra Recommendations when** you want a quick, portal-based health check of your tenant's fundamentals — it's built-in and free.

**Use Defender for Identity when** you have on-premises Active Directory and need to detect Kerberos misconfigurations, lateral movement paths, and certificate services issues.

**Use EntraLint when** you need identity security checks in your CI/CD pipeline, want to gate deployments on identity posture, need to track configuration drift between scans, require compliance framework mappings (CIS, CISA SCuBA, NIST) per finding, want to lint service principal permissions and app credential hygiene in depth, or need to audit the new Entra Agent ID surface.

EntraLint is not a replacement for Secure Score — it's a complement. Run both. Secure Score gives you a portal-based overview of your tenant's health; EntraLint gives you a CLI-first linter that fits into your DevOps pipeline.

## Quick Start

EntraLint requires Python 3.11+ and [uv](https://docs.astral.sh/uv/) (a fast Python package manager).

The fastest way to run EntraLint is to **reuse your existing Azure CLI sign-in** — no app registration, no client secret, nothing to configure in Entra ID.

```bash
# 1. Clone and install
git clone https://github.com/bgdnext64/EntraLint.git
cd EntraLint
uv sync

# 2. Sign in with the Azure CLI (you almost certainly already have this)
az login --tenant contoso.onmicrosoft.com

# 3. Tell EntraLint to reuse that sign-in, then scan
#    PowerShell:
$env:ENTRALINT_USE_DEFAULT_CREDENTIAL = "true"
#    bash / zsh:
#    export ENTRALINT_USE_DEFAULT_CREDENTIAL=true
uv run entralint scan --tenant contoso.onmicrosoft.com
```

That's it. EntraLint reuses the Microsoft Graph access your `az login` session already has, scans your tenant's configuration through the Microsoft Graph API, and prints the results directly in your terminal. **You do not need to register an application** for this path.

Prefer an interactive browser login, or need an unattended identity for CI/CD? See [Authentication](#authentication) for every option — including device-code sign-in and a dedicated read-only app registration.

### What You'll See

EntraLint prints color-coded findings as each check runs. Here's an
example highlighting the **Entra Agent ID** category — the newest and
most under-tooled identity surface in Entra ID:

```
╭─ EntraLint v0.1.0 ──────────────────────────────────────────────────────╮
│ Tenant: contoso.onmicrosoft.com                                         │
│ Checks: 88 | Framework: All                                             │
╰─────────────────────────────────────────────────────────────────────────╯

Collecting data from Microsoft Graph API...
  ✓ Organization settings
  ✓ Conditional Access policies
  ✓ Users (3,847)
  ✓ Applications (142)
  ✓ Service Principals (891)
  ✓ Role Assignments
  ✓ Agent Identities (7 agents, 12 blueprints)

Running security checks...

 CRITICAL  entraid_agent_001  Agent 'finance-bot' holds dangerous permission RoleManagement.ReadWrite.Directory
 CRITICAL  entraid_agent_002  Blueprint 'corp-copilot-bp' uses allAllowedScopes inheritance (any permission its sponsor has)
 HIGH      entraid_agent_003  Agent 'helpdesk-bot' holds blocked permission Files.ReadWrite.All
 HIGH      entraid_agent_004  Agent 'data-summarizer' has overly broad scope (Mail.ReadWrite + Files.ReadWrite.All + Sites.ReadWrite.All)
 HIGH      entraid_agent_005  Agent 'rogue-poc' created by external app 14d82eec-204b-4c2f-b7e8-296a70dab67e (not on allowlist)
 HIGH      entraid_agent_006  Blueprint 'team-assistant-bp' has no owner or sponsor
 MEDIUM    entraid_agent_008  Blueprint 'legacy-bot-bp' uses client secrets instead of federated credentials
 MEDIUM    entraid_agent_010  Blueprint 'corp-copilot-bp' has no inheritable permission restrictions
 LOW       entraid_agent_012  Blueprint 'team-assistant-bp' has no description
 PASS      entraid_agent_007  No external agent blueprint principals found
 PASS      entraid_agent_009  No stale agent identities (>180 days)
 PASS      entraid_agent_011  No agent identity is disabled by Microsoft

 CRITICAL  entraid_ca_001     No CA policy requires MFA for all users
 CRITICAL  entraid_role_001   6 permanent Global Admin assignments (max: 4)
 HIGH      entraid_app_006    12 apps with secrets expiring within 30 days
 PASS      entraid_ca_002     Legacy authentication blocked
 PASS      entraid_auth_001   Security defaults disabled (CA in use)

╭─ Summary ───────────────────────────────────────────────────────────────╮
│  Passed: 48  Failed: 17  Skipped: 5                                     │
╰─────────────────────────────────────────────────────────────────────────╯
```

#### What those agent findings mean

The Entra Agent ID surface is brand new — agent identities became GA in
Microsoft Graph v1.0 in March 2026 — and most security tools haven't
caught up yet. Here's why each line above matters:

| Finding | Why it's risky |
|---|---|
| **`entraid_agent_001` — Dangerous permission** | An AI agent holding `RoleManagement.ReadWrite.Directory` can grant itself or anyone else any directory role, including Global Administrator. Treat agent permissions like service principal permissions: least privilege only. |
| **`entraid_agent_002` — `allAllowedScopes` inheritance** | A blueprint configured with `allAllowedScopes` lets every agent built from it inherit *any* permission its sponsor has. This collapses RBAC: a single misconfigured sponsor user grants the entire fleet of agents broad access. |
| **`entraid_agent_003` — Blocked permission** | The tenant's permission grant policy explicitly forbade `Files.ReadWrite.All` for agents, but this agent acquired it anyway (likely via a blueprint update before policy enforcement). Indicates a drift or policy bypass. |
| **`entraid_agent_004` — Overly broad scope** | The agent has multiple high-impact permissions across mail, files, and SharePoint. If credentials leak or the model is prompt-injected, the blast radius is the entire user data plane. |
| **`entraid_agent_005` — Unauthorized creator** | The agent was created by an external app registration that isn't on your allowlist. Agents created by unknown apps are an exfiltration vector — anyone with a valid Graph token from that external app could spawn agents in your tenant. |
| **`entraid_agent_006` — No owner / sponsor** | An ownerless blueprint has no human accountable for review or revocation. When the original creator leaves, the blueprint becomes a permanent orphan. |
| **`entraid_agent_008` — Client secrets** | Agents using long-lived client secrets are stealable; federated credentials (workload identity federation) avoid the secret entirely. |
| **`entraid_agent_010` — No inheritable restrictions** | The blueprint doesn't define a permission ceiling, so future agents created from it can request whatever they want. Best practice is to declare the maximum permission set at the blueprint level. |
| **`entraid_agent_012` — No description** | Audit hygiene only, but matters at scale: when a tenant has dozens of agents, "what does this one do?" needs a fast answer. |

EntraLint ships **all 18** Entra Agent ID checks today, covering
permissions, blueprint inheritance, ownership, credentials, lifecycle,
multi-tenant exposure, federated-credential hygiene, and origin/creator.
See [`uv run entralint list-checks --category AgentIdentity`](#cli-reference)
for the full list.

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

## Authentication

EntraLint offers several ways to authenticate, from zero-setup local scans to unattended CI/CD. Pick the one that matches how you're running it.

### Do I need to register an app?

**No — not for local, interactive use.** If you can already run `az login` against your tenant, EntraLint can reuse that session (Option 1 below). This is the recommended way to try EntraLint and to run it from your own workstation.

You **only** need a dedicated app registration when you want:

- an unattended, non-interactive identity for CI/CD pipelines or scheduled scans, or
- a strictly scoped read-only identity that's independent of any user account, or
- a persistent cached browser login (device-code flow).

### Option 1 — Reuse your `az login` session (no app registration)

Best for: local development, ad-hoc scans, trying EntraLint.

```bash
az login --tenant <your-tenant>

# PowerShell
$env:ENTRALINT_USE_DEFAULT_CREDENTIAL = "true"
# bash / zsh
# export ENTRALINT_USE_DEFAULT_CREDENTIAL=true

uv run entralint scan --tenant <your-tenant>
```

EntraLint uses `DefaultAzureCredential` under the hood, so this same setting also transparently picks up a **managed identity** (when running on Azure) or **workload identity federation** (GitHub Actions OIDC) with no code changes.

> **Scope note:** this path inherits whatever Microsoft Graph permissions your Azure CLI sign-in already has. That covers most checks, but a few policy-heavy checks (for example Security Defaults or the authentication-methods policy) may be skipped if your account hasn't been granted `Policy.Read.All`. For complete coverage, use a dedicated app registration (Option 3) with all [required permissions](#permissions) consented.

### Option 2 — Device-code sign-in (interactive, needs a public app registration)

Best for: interactive use where you want a persistent cached login and full permission coverage.

Device-code flow needs a **public client** app registration whose ID you supply via `ENTRALINT_CLIENT_ID` (or `--client-id`). Once that's set:

```bash
export ENTRALINT_CLIENT_ID="<your-public-app-client-id>"   # or pass --client-id
uv run entralint login --tenant <your-tenant>              # prints a URL + code to enter in a browser
uv run entralint scan  --tenant <your-tenant>              # reuses the cached token
```

The token is cached per-tenant under `~/.entralint/cache/`, so you sign in once until it expires.

### Option 3 — App registration with client secret or certificate (CI/CD, unattended)

Best for: pipelines and scheduled scans with a scoped, read-only identity.

Register an app, grant it the [required read-only permissions](#permissions), then provide the credentials via environment variables:

```bash
export ENTRALINT_TENANT_ID="<tenant-id>"
export ENTRALINT_CLIENT_ID="<app-client-id>"
export ENTRALINT_CLIENT_SECRET="<client-secret>"          # or ENTRALINT_CLIENT_CERTIFICATE_PATH=/path/to/cert.pem
uv run entralint scan --fail-on high -f sarif --output-file results.sarif
```

### How EntraLint picks a method

`entralint scan` auto-detects the authentication method from the environment, in this priority order:

1. **Workload identity federation** — if `AZURE_FEDERATED_TOKEN_FILE` / GitHub OIDC is present
2. **Managed identity** — if `IDENTITY_ENDPOINT` is present (Azure-hosted)
3. **Explicit `DefaultAzureCredential`** — if `ENTRALINT_USE_DEFAULT_CREDENTIAL=true` (the `az login` path)
4. **Client credentials** — if `ENTRALINT_CLIENT_SECRET` or `ENTRALINT_CLIENT_CERTIFICATE_PATH` is set
5. **Cached device-code token** — falls back to the token saved by `entralint login`

| Method | App registration? | Interactive? | Best for |
|---|---|---|---|
| `az login` + `ENTRALINT_USE_DEFAULT_CREDENTIAL` | **No** | Yes (via `az`) | Local, ad-hoc scans |
| Managed identity / WIF | Federated (no secret) | No | Azure-hosted, GitHub Actions OIDC |
| Device code (`entralint login`) | Yes (public client) | Yes | Persistent local login |
| Client secret / certificate | Yes (confidential) | No | CI/CD, scheduled scans |

## Security Checks (88)

EntraLint ships with 88 built-in checks organized into 8 categories:

| Category | Count | Severities | What It Covers |
|---|---|---|---|
| Conditional Access | 14 | 3 Critical, 5 High, 3 Medium | MFA enforcement, legacy auth blocking, device compliance, sign-in/user risk policies, device code flow |
| Authentication | 10 | 1 Critical, 1 High, 4 Medium, 2 Low | Password protection, banned passwords, SSPR, FIDO2, Authenticator number matching, TAP lifetime |
| Privileged Roles | 10 | 4 Critical, 3 High, 1 Medium | PIM usage, Global Admin count, standing assignments, activation approval, emergency access accounts |
| Applications | 9 | 3 Critical, 5 High, 4 Medium | Expired/long-lived secrets, excessive Graph permissions, no owners, unrestricted user consent |
| Service Principals | 9 | 1 High, 6 Medium, 2 Low | Expired credentials, high-privilege grants, dual credential types, stale SPs |
| Users & Guests | 9 | 1 Critical, 2 High, 3 Medium, 1 Low | Stale accounts, guest access level, MFA registration, disabled users with roles |
| Organization | 9 | 1 High, 7 Medium, 1 Low | Security defaults, verified domains, cross-tenant trust settings |
| Agentic Identity | 18 | 2 Critical, 7 High, 7 Medium, 2 Low | AI agent permissions, blueprint scope inheritance, blocked permission enforcement, multi-tenant blueprints, federated-credential misconfig, delegated high-privilege grants, orphaned/disabled agents, stale agents |

Every check includes:

- A severity level (Critical, High, Medium, Low)
- Compliance framework mappings (CIS, CISA SCuBA, NIST 800-53)
- A description of the risk
- Remediation guidance with links to Microsoft documentation

### Agentic Identity Checks

EntraLint is the first security scanner to provide dedicated checks for **Microsoft Entra Agent ID** — the identity platform that gives AI agents their own first-class identity type in Entra ID (Graph API v1.0 since March 2026). These 18 checks cover agent blueprints, blueprint principals, and agent identity instances, detecting issues like:

- Agents holding dangerous or blocked permissions (e.g., `Files.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`)
- Blueprints using `allAllowedScopes` inheritance (allows agents to inherit any permission)
- Multi-tenant agent blueprints exposed to external tenants
- Federated identity credential (FIC) misconfigurations, such as wildcard subjects
- Agent service principals granted broad delegated permissions
- Orphaned agents and blueprints with no owner or sponsor
- Disabled agents that still hold access, and stale agent identities with valid credentials
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
        uses: bgdnext64/EntraLint@v0.1.0
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
        uses: bgdnext64/EntraLint@v0.1.0
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

You can extend EntraLint with your own security checks. Custom checks work exactly like built-in checks — they're auto-discovered, run alongside all other checks, and appear in every output format (table, JSON, SARIF, HTML).

### Where to Put Custom Checks

EntraLint auto-discovers custom checks from these locations (no config needed for the first two):

| Location | When to Use |
|---|---|
| `~/.entralint/custom_checks/` | Personal checks that apply to all your projects |
| `.entralint/checks/` (in your project) | Team checks committed to your repo |
| Any path in `custom_checks_dirs` config | Custom paths defined in `.entralint.yaml` |

Custom check files can be **standalone `.py` files** — no `__init__.py`, no package structure required. Just drop a `.py` file in one of the directories above.

### Step-by-Step: Writing a Custom Check

**1. Create the check file:**

```bash
mkdir -p .entralint/checks
```

**2. Write the check class** — here's a complete, working example:

```python
# .entralint/checks/check_no_display_name.py

from entralint.core.check import BaseCheck, CheckMetadata, Finding, Remediation, Severity, Status
from entralint.core.context import TenantContext


class CheckNoDisplayName(BaseCheck):
    """Flag service principals with no display name."""

    def __init__(self) -> None:
        super().__init__(
            metadata=CheckMetadata(
                check_id="custom_sp_001",
                check_title="Service principals should have a display name",
                service_name="Service Principals",
                severity=Severity.LOW,
                resource_type="ServicePrincipal",
                description="Identifies service principals with an empty or missing display name, making audit and incident response harder.",
                risk="Unnamed service principals are difficult to identify during security reviews and incident response.",
                remediation=Remediation(
                    recommendation="Set a descriptive display name on every service principal.",
                    url="https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/add-application-portal",
                ),
                required_permissions=["Application.Read.All"],
            ),
        )

    def execute(self, context: TenantContext) -> list[Finding]:
        findings: list[Finding] = []

        for sp in context.service_principals:
            if not sp.display_name or not sp.display_name.strip():
                findings.append(
                    Finding(
                        check_id=self.metadata.check_id,
                        status=Status.FAIL,
                        severity=self.metadata.severity,
                        resource_type="ServicePrincipal",
                        resource_id=sp.id,
                        title=f"Service principal {sp.app_id} has no display name",
                        description=f"AppId: {sp.app_id}",
                        remediation=self.metadata.remediation.recommendation,
                    )
                )

        if not findings:
            findings.append(
                Finding(
                    check_id=self.metadata.check_id,
                    status=Status.PASS,
                    severity=self.metadata.severity,
                    title="All service principals have a display name",
                )
            )

        return findings
```

**3. Run it:**

```bash
uv run entralint scan
```

Your check appears automatically in the results — no registration, no config changes.

### Available Data in `TenantContext`

The `context` parameter in `execute()` gives you access to all data fetched from the tenant:

| Field | Type | Description |
|---|---|---|
| `context.users` | `list[User]` | All users (members and guests) |
| `context.applications` | `list[Application]` | App registrations |
| `context.service_principals` | `list[ServicePrincipal]` | Service principals (enterprise apps) |
| `context.conditional_access_policies` | `list[ConditionalAccessPolicy]` | CA policies |
| `context.role_assignments` | `list[DirectoryRoleAssignment]` | Directory role assignments |
| `context.app_role_assignments` | `list[AppRoleAssignment]` | App role grants |
| `context.oauth2_permission_grants` | `list[dict]` | Delegated permission grants |
| `context.organization` | `Organization` | Tenant org info, verified domains |
| `context.authentication_methods_policy` | `dict` | Auth methods policy (MFA, FIDO2, etc.) |
| `context.authorization_policy` | `dict` | Authorization policy settings |
| `context.security_defaults_policy` | `dict` | Security defaults state |
| `context.cross_tenant_access_policy` | `dict` | Cross-tenant access settings |
| `context.named_locations` | `list[dict]` | Named/trusted locations |
| `context.agent_identities` | `list[AgentIdentity]` | Agent identity instances |
| `context.agent_identity_blueprints` | `list[AgentIdentityBlueprint]` | Agent blueprints |
| `context.tenant_id` | `str` | Tenant GUID |
| `context.granted_permissions` | `set[str]` | Permissions the scan has |

### Findings: PASS vs FAIL

Every check must return a `list[Finding]`. The key rules:

- Return `Status.FAIL` for each resource that violates the check
- Return a single `Status.PASS` if everything looks good
- Always set `check_id` to match your `metadata.check_id`
- Set `resource_id` on FAIL findings so users know which resource to fix
- The `remediation` field on a Finding is the text shown to the user

### Optional: Metadata JSON File

Instead of defining metadata in Python, you can use a separate JSON file. This is how the built-in checks work — it keeps the Python file focused on logic:

```
.entralint/checks/
    check_no_display_name/
        __init__.py                              # empty file
        check_no_display_name.py                 # check class
        check_no_display_name.metadata.json      # metadata
```

The JSON uses PascalCase keys:

```json
{
    "CheckID": "custom_sp_001",
    "CheckVersion": "1.0.0",
    "CheckTitle": "Service principals should have a display name",
    "ServiceName": "Service Principals",
    "Severity": "LOW",
    "ResourceType": "ServicePrincipal",
    "Description": "Identifies service principals with an empty or missing display name.",
    "Risk": "Unnamed service principals are difficult to identify during reviews.",
    "Remediation": {
        "Recommendation": "Set a descriptive display name on every service principal.",
        "Url": "https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/add-application-portal"
    },
    "RequiredPermissions": ["Application.Read.All"],
    "RequiredLicense": null,
    "DependsOn": [],
    "Frameworks": []
}
```

### Verify Your Check

```bash
# Confirm your check is discovered
uv run entralint list-checks | grep custom

# See full details
uv run entralint show-check custom_sp_001

# Run only your check
uv run entralint scan --checks custom_sp_001
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

# Run the test suite (503 tests)
uv run pytest

# Lint
uv run ruff check src/ tests/

# Type check
uv run mypy

# Optional: enable pre-commit hooks (ruff + mypy + hygiene checks)
pipx install pre-commit
pre-commit install
```

### Writing a new check

See [`docs/authoring-checks.md`](docs/authoring-checks.md) for a
step-by-step walkthrough of adding a new built-in check, including the
metadata JSON schema and required test coverage.

### Project Structure

```
src/entralint/
├── cli/          # Typer CLI commands and Rich output formatting
├── core/         # Check engine, Pydantic models, TenantContext
├── auth/         # MSAL authentication (device code, client credentials)
├── graph/        # Graph API client, caching, pagination, rate limiting
├── checks/       # 88 built-in security checks (auto-discovered)
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

## Demo Tenant Seeding

[`scripts/seed_demo_findings.ps1`](scripts/seed_demo_findings.ps1) is a
companion script that intentionally **"dorks"** a non-production Entra ID
tenant so EntraLint has realistic findings to demonstrate against. It can
also reverse every change it makes.

> **Run this only against a dedicated demo or experimentation tenant.** It
> creates real applications, service principals, users, agent identities,
> and patches the tenant `authorizationPolicy`. Never point it at a tenant
> that contains anything you care about.

### What it seeds

The script is divided into three independent groups so you can scope what
gets created.

**Tier 1 — Safe, easily reversible (default).** Triggers ~10 EntraLint
checks across 4 categories:

| Created object / change                                       | Triggers                       |
| ------------------------------------------------------------- | ------------------------------ |
| App registration declaring `RoleManagement.ReadWrite.Directory`, `Application.ReadWrite.All`, `Directory.ReadWrite.All` | `entraid_app_005` (HIGH)       |
| Same app + a non-admin user added as owner                    | `entraid_app_007` (CRITICAL)   |
| App requesting many delegated scopes (`Files.ReadWrite.All`, `Mail.ReadWrite`, `Group.ReadWrite.All`, `Directory.AccessAsUser.All`) | `entraid_app_009` (MEDIUM) |
| Disabled service principal that still has a password credential and a self-signed cert | `entraid_sp_001` (HIGH), `entraid_sp_009` (LOW) |
| Disabled member account                                       | `entraid_user_002` (LOW)       |
| 3 invited guest users (to `*@example.com`)                    | `entraid_user_001`, `_006`, `_008` |
| `authorizationPolicy` patched: `allowInvitesFrom = everyone`, `allowedToCreateApps = true`, broad user-consent permission grant policy | `entraid_org_002` (HIGH), `_003` (MEDIUM), `_009` (MEDIUM) |

**Tier 2 — Privileged role assignments (opt-in, requires confirmation).**

| Created object / change                                       | Triggers                       |
| ------------------------------------------------------------- | ------------------------------ |
| Guest user assigned `Directory Reader`                        | `entraid_role_004` (CRITICAL)  |
| Service principal assigned `Directory Reader`                 | `entraid_role_005` (CRITICAL)  |
| Member user assigned `Application Administrator`              | `entraid_role_009` (MEDIUM)    |
| Member user assigned `Cloud Application Administrator`        | `entraid_role_010` (MEDIUM)    |

**Agent identities — `-Agent` switch (independent of tier).** Builds on
the manual [`scripts/create_test_agents.ps1`](scripts/create_test_agents.ps1)
but tagged for teardown:

- 7 agent identity blueprints: well-formed / no-description / overprivileged / secret-based / multi-tenant / misconfigured-FIC / no-sponsor
- A blueprint principal for each, plus 6 agent identities — including a no-sponsor agent, one granted a high-risk delegated scope (`Mail.ReadWrite`), and one disabled while retaining an app role

These trigger `entraid_agent_008`, `_010`, `_012`, `_013`, `_014`, `_015`,
`_017`, and `_018`. A few (the delegated grant and app-role assignment)
need Global Administrator / privileged-role rights on the signed-in
account; the script logs a warning and continues if they're rejected.

### How safety works

1. **Naming prefix.** Every created object has a configurable display-name
   prefix (default `EntraLint-Demo-`) and a timestamp suffix.
2. **State file.** The script writes `scripts/.demo-state.json` recording
   the GUID of every object it creates and a snapshot of any policy it
   modified before mutation.
3. **Teardown reads only the state file.** It never blanket-deletes by
   prefix or by name — it deletes exactly the GUIDs it recorded.
   Re-running a teardown after teardown is a no-op.
4. **Policy snapshots.** When it patches `authorizationPolicy`, the
   pre-patch values are captured into the state file. Teardown PATCHes
   the original values back.
5. **`-WhatIf` and `ShouldProcess`.** Every Graph mutation goes through
   PowerShell's `ShouldProcess`, so `-WhatIf` enumerates exactly what
   would happen without calling Graph. Tier 2 and Teardown additionally
   require interactive confirmation (`-Force` to skip).
6. **Tenant guard.** The script reads `az account show` and refuses to
   run if the active session's tenant doesn't match `-TenantId` (when
   provided), preventing accidental cross-tenant runs.

### Authentication

The script uses your existing `az` CLI session. Sign in first to the
target tenant:

```powershell
az login --tenant <demo-tenant-id-or-domain>
```

The signed-in identity needs:

- `Application.ReadWrite.All` (apps, SPs, agent blueprints)
- `User.ReadWrite.All` and `User.Invite.All` (users + guests)
- `Policy.ReadWrite.Authorization` (org policy)
- `RoleManagement.ReadWrite.Directory` (Tier 2 only)
- `AgentIdentity.ReadWrite.All` and `AgentIdentityBlueprint.ReadWrite.All` (`-Agent` only)

In a demo tenant, simply being a Global Administrator is sufficient.

### Prerequisites

| Required for | What you need |
|---|---|
| All operations | PowerShell 7+ (`pwsh`), [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) signed in via `az login --tenant <demo-tenant>` |
| `-Agent` switch | The Microsoft Graph PowerShell auth module: `Install-Module Microsoft.Graph.Authentication -Scope CurrentUser` |
| Tier 2 / Teardown | Same as above (no extra modules) |

> **Note on agent identities.** Microsoft's Agent APIs reject any token
> that includes `Directory.AccessAsUser.All` (which `az` always requests).
> The script handles this transparently: when `-Agent` is used, it loads
> `Microsoft.Graph.Authentication` and connects with only the
> `AgentIdentity.ReadWrite.All` and `Application.ReadWrite.All` scopes
> for blueprint and agent operations, falling back to `az rest` for
> everything else.

### Usage

```powershell
# Dry-run everything — prints what would be created without calling Graph
./scripts/seed_demo_findings.ps1 -Tier All -Agent -WhatIf

# Default Tier 1 only
./scripts/seed_demo_findings.ps1

# Tier 1 + agent identities
./scripts/seed_demo_findings.ps1 -Tier 1 -Agent

# Add Tier 2 later (will prompt for confirmation; -Force to skip)
./scripts/seed_demo_findings.ps1 -Tier 2

# Reverse everything recorded in the state file
./scripts/seed_demo_findings.ps1 -Action Teardown

# Custom prefix / state file (rare)
./scripts/seed_demo_findings.ps1 -Prefix 'MyCo-Lint-' -StateFile ./demo.json
```

### Demo workflow

```powershell
# 1. Baseline scan — should be mostly green on a fresh tenant
uv run entralint scan --tenant <demo-tenant>

# 2. Seed misconfigurations
./scripts/seed_demo_findings.ps1 -Tier 1 -Agent

# 3. Re-scan — typically adds 25-35 new findings depending on tier/agent flags
uv run entralint scan --tenant <demo-tenant> --no-cache

# 4. Generate a shareable HTML report from the same data
uv run entralint scan --tenant <demo-tenant> --no-cache -f html --output-file demo.html

# 5. Tear it all down when finished
./scripts/seed_demo_findings.ps1 -Action Teardown
```

### Limitations

- Findings that depend on **tenant-wide policy state** that requires Entra
  ID **P1/P2** (Conditional Access, Identity Protection, sign-in risk)
  cannot be seeded by this script and will continue to surface as
  pre-existing findings (or be skipped with a permission notice).
- The script does not seed `entraid_role_001` (extra Global Admins) or
  `entraid_sp_003` (admin-consent of high-priv permissions) even in
  Tier 2 — these are intentionally omitted because they are easy to
  forget to remove and have a real blast radius.
- Microsoft-managed first-party service principals (e.g. Defender for
  Containers) sometimes have expired credentials and will trigger
  `entraid_sp_008`. These are out of scope for the demo script.
- Some tenants block **B2B guest invitations** at the cross-tenant access
  policy level (`Forbidden: Guest invitations not allowed for your
  company`). The script logs a warning, skips that step, and continues
  — `entraid_user_001`/`_006`/`_008` will not fire on those tenants.

## License

AGPL-3.0 — See [LICENSE](LICENSE) for details.

## Disclaimer

EntraLint is an independent open-source project created and maintained by Brian Davis. It is provided "as is" without warranty of any kind. This project is **not** affiliated with, officially maintained by, endorsed by, or sponsored by Microsoft Corporation. All product names, trademarks, and registered trademarks are the property of their respective owners.
