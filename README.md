# EntraLint

**Lint your Entra ID. Fix before they breach.**

EntraLint is an open-source, CLI-first security linter for Microsoft Entra ID (Azure AD). It scans your tenant for misconfigurations, maps findings to compliance frameworks (CIS, CISA SCuBA, NIST 800-53), and integrates into CI/CD pipelines via SARIF output.

## Quick Start

```bash
# Install dependencies
pip install uv
uv sync

# Authenticate (device-code flow)
uv run entralint login

# Scan your tenant
uv run entralint scan
```

## Features

- **70 security checks** across 8 categories — conditional access, authentication methods, privileged roles, applications, service principals, users/guests, organization settings, cross-tenant access
- **Compliance mapping** — CIS Microsoft 365 Foundations Benchmark v5, CISA SCuBA (BOD 25-01), NIST 800-53
- **4 output formats** — Rich table (default), JSON, SARIF 2.1.0, self-contained HTML
- **Data caching** — SQLite-backed local cache with per-endpoint TTL; rescan instantly offline
- **Offline mode** — `--offline` runs all checks against cached data with zero API calls
- **Custom checks** — Drop Python checks into `~/.entralint/custom_checks/` or `.entralint/checks/` for auto-discovery
- **Baseline support** — Track finding drift with `--baseline`, `--update-baseline`, and `--fail-on-new`
- **Configuration file** — `.entralint.yaml` for suppressions, severity overrides, exclusions, and custom check directories
- **CI/CD native** — SARIF for GitHub Code Scanning, `--fail-on` exit codes, `--quiet` mode

## CLI Commands

| Command | Description |
|---|---|
| `scan` | Scan tenant for security misconfigurations |
| `login` | Authenticate via device-code flow |
| `list-checks` | List available checks (filter by `--category`, `--severity`) |
| `show-check <ID>` | Display full metadata for a check |
| `explain <ID>` | Alias for `show-check` |
| `list-frameworks` | List supported compliance frameworks |
| `cache` | Manage local data cache (`--status`, `--clear`, `--tenant`) |
| `report` | Generate reports from cached scan data |
| `config` | Manage configuration |
| `version` | Show version |

## Scan Options

```
--tenant TEXT        Tenant ID or domain to scan
--format/-f TEXT     Output format: table, json, sarif, html
--output-file TEXT   Write report to file
--fail-on TEXT       Exit non-zero at severity threshold (critical/high/medium/low)
--checks TEXT        Comma-separated check IDs to run
--category TEXT      Filter by category
--severity TEXT      Filter by severity
--no-cache           Bypass local data cache
--offline            Scan against cached data only (no API calls)
--config PATH        Path to .entralint.yaml
--baseline PATH      Compare against baseline file
--update-baseline    Save current scan as new baseline
--fail-on-new        Exit non-zero only for NEW findings vs baseline
--quiet/-q           Suppress console output (CI mode)
--verbose/-v         Verbose output
```

## Security Checks (70)

| Category | Count | Examples |
|---|---|---|
| Conditional Access | 14 | MFA for all users, block legacy auth, require compliant devices |
| Authentication | 10 | Password protection, SSPR, FIDO2 enabled, TAP lifetime |
| Privileged Roles | 10 | PIM enabled, GA count, standing admin assignments |
| Applications | 9 | Expired credentials, excessive permissions, public clients |
| Service Principals | 9 | Expired creds, high-priv grants, dual credential types |
| Users | 9 | Stale accounts, guest access reviews, disabled users with roles |
| Organization | 9 | Security defaults, verified domains, cross-tenant trust |
| *Cross-check* | — | *Above totals 70 checks* |

## Configuration

Create `.entralint.yaml` in your project root:

```yaml
suppress:
  - check_id: ca_003
    reason: "Legacy VPN exception approved by CISO"

overrides:
  ca_001:
    severity: critical

exclude_checks:
  - org_001

fail_on: high

baseline: .entralint-baseline.json

custom_checks_dirs:
  - ./my-checks
```

## Custom Checks

Create a Python file in `~/.entralint/custom_checks/` or `.entralint/checks/`:

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
        # Your logic here
        return [Finding(status=Status.PASS, title="All good")]
```

## Development

```bash
git clone https://github.com/bgdnext64/EntraLint.git
cd EntraLint
uv sync

# Run the CLI
uv run entralint version

# Run tests (378 tests)
uv run pytest

# Lint
uv run ruff check src/ tests/

# Type check
uv run mypy
```

## License

AGPL-3.0 — See [LICENSE](LICENSE) for details.
