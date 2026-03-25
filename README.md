# EntraLint

**Lint your Entra ID. Fix before they breach.**

EntraLint is an open-source, CLI-first security linter for Microsoft Entra ID. It detects misconfigurations, maps findings to compliance frameworks (CIS, CISA SCuBA, NIST), and integrates into CI/CD pipelines.

## Quick Start

```bash
pip install entralint
entralint login
entralint scan
```

## Features

- **70 security checks** across 8 categories — conditional access, MFA, privileged roles, apps, guests, stale accounts, auth policies, cross-tenant
- **Compliance mapping** — CIS Microsoft 365 v5/v6, CISA SCuBA (BOD 25-01), NIST 800-53
- **Multiple output formats** — HTML, JSON, SARIF, CSV, Markdown, PDF
- **Multi-tenant scanning** — first-class MSP support with per-tenant token isolation
- **CI/CD native** — SARIF for GitHub Code Scanning, exit codes for pipeline gates

## Development

```bash
# Install uv if you haven't already
pip install uv

# Clone and install in development mode
git clone https://github.com/entralint/entralint.git
cd entralint
uv sync

# Run the CLI
uv run entralint version

# Run tests
uv run pytest

# Lint and type check
uv run ruff check src/ tests/
uv run mypy
```

## License

AGPL-3.0 — See [LICENSE](LICENSE) for details.
