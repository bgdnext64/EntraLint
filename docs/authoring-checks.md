# Authoring a new EntraLint check

This guide walks through adding a brand-new security check to EntraLint. A
check is a small Python class that inspects the cached tenant data
(`TenantContext`) and emits one or more `Finding` objects.

## 1. Pick a category and ID

Checks live under `src/entralint/checks/<category>/<check_slug>/`. The
existing categories are:

| Category            | Purpose                                 |
| ------------------- | --------------------------------------- |
| `agent_identity`    | AI agent identities & blueprints        |
| `applications`      | App registrations                       |
| `authentication`    | Authentication methods & policies       |
| `conditional_access`| Conditional Access policies             |
| `organization`      | Tenant-wide org settings                |
| `privileged_roles`  | Directory role assignments & PIM        |
| `service_principals`| Enterprise applications (SPs)           |
| `users`             | User accounts                           |

Pick a stable `CheckID` of the form `entraid_<area>_<NNN>` (e.g.
`entraid_user_021`). IDs are user-visible, show up in reports, and must
be unique across the codebase.

## 2. Create the three files

Each check lives in its own package with three files:

```
src/entralint/checks/<category>/<check_slug>/
├── __init__.py                   # empty
├── <check_slug>.py               # the check class
└── <check_slug>.metadata.json    # metadata (title, severity, …)
```

### 2a. `<check_slug>.metadata.json`

```json
{
  "CheckID": "entraid_user_021",
  "CheckVersion": "1.0.0",
  "CheckTitle": "Short human-readable title",
  "ServiceName": "Users",
  "Severity": "MEDIUM",
  "ResourceType": "User",
  "Description": "What this check looks at and why.",
  "Risk": "What goes wrong if the misconfiguration is present.",
  "Remediation": {
    "Recommendation": "Plain-language fix guidance.",
    "Url": "https://learn.microsoft.com/..."
  },
  "Frameworks": [
    {
      "framework": "CIS_M365_v5",
      "controls": ["5.1.3.1"],
      "verified": false,
      "source": "AI-generated mapping — not yet verified"
    }
  ],
  "GraphAPIEndpoints": ["/users"],
  "RequiredPermissions": ["User.Read.All"],
  "RequiredLicense": null,
  "DependsOn": [],
  "SourceNotes": ""
}
```

Severity must be one of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`. Set
`verified: false` on framework mappings unless you have cross-checked the
control ID against the published benchmark PDF.

### 2b. `<check_slug>.py`

```python
"""Check: One-line summary of what this check enforces."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from entralint.core.check import (
    BaseCheck,
    CheckMetadata,
    Finding,
    Remediation,
    Severity,
    Status,
)

if TYPE_CHECKING:
    from entralint.core.context import TenantContext

_METADATA_PATH = Path(__file__).parent / "user_no_mfa_methods.metadata.json"


def _load_metadata() -> CheckMetadata:
    raw = json.loads(_METADATA_PATH.read_text(encoding="utf-8"))
    rem = raw["Remediation"]
    return CheckMetadata(
        check_id=raw["CheckID"],
        check_version=raw["CheckVersion"],
        check_title=raw["CheckTitle"],
        service_name=raw["ServiceName"],
        severity=Severity(raw["Severity"]),
        resource_type=raw["ResourceType"],
        description=raw["Description"],
        risk=raw["Risk"],
        remediation=Remediation(
            recommendation=rem["Recommendation"],
            url=rem.get("Url", ""),
        ),
        frameworks=raw["Frameworks"],
        graph_api_endpoints=raw["GraphAPIEndpoints"],
        required_permissions=raw["RequiredPermissions"],
        required_license=raw.get("RequiredLicense"),
        depends_on=raw.get("DependsOn", []),
        source_notes=raw.get("SourceNotes", ""),
    )


class UserNoMfaMethods(BaseCheck):
    """Flags users who have zero MFA methods registered."""

    metadata = _load_metadata()

    def __init__(self) -> None:
        super().__init__(metadata=self.metadata)

    def execute(self, context: TenantContext) -> list[Finding]:
        if not context.users:
            return self.skip(
                "No user data available",
                status=Status.SKIPPED_PERMISSION,
            )

        offenders = [u for u in context.users if not u.registered_auth_methods]
        if not offenders:
            return [
                Finding(
                    check_id=self.metadata.check_id,
                    check_version=self.metadata.check_version,
                    status=Status.PASS,
                    severity=self.metadata.severity,
                    resource_type=self.metadata.resource_type,
                    title="All active users have MFA methods registered",
                    description="",
                )
            ]

        return [
            Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=Status.FAIL,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                resource_id=u.id,
                title=f"User {u.display_name} has no MFA methods",
                description="User cannot complete an MFA challenge.",
                remediation=self.metadata.remediation.recommendation,
                frameworks=self.metadata.frameworks,
            )
            for u in offenders
        ]
```

### 2c. `__init__.py`

Leave this file empty — it just makes the directory a Python package so
`CheckEngine` can discover it.

## 3. Use the right status

| Status                | When to use                                                       |
| --------------------- | ----------------------------------------------------------------- |
| `Status.PASS`         | The control is configured correctly.                              |
| `Status.FAIL`         | The tenant has the misconfiguration this check targets.           |
| `Status.SKIPPED_PERMISSION` | Required Graph permission wasn't granted or data is missing. |
| `Status.SKIPPED_LICENSE`   | The check needs a license the tenant does not have (e.g. P1). |
| `Status.SKIPPED_DEPENDENCY`| A check in `depends_on` did not PASS.                         |
| `Status.ERROR`        | The check itself threw unexpectedly. Prefer skipping over this.   |

Use `self.skip(reason, status=Status.SKIPPED_PERMISSION)` for the common
"couldn't run" case; it returns a properly-shaped single-finding list.

## 4. Add tests

Place tests in `tests/unit/checks/test_<check_slug>.py`. Use the
`TenantContext(**kwargs)` constructor to build synthetic scenarios —
avoid mocking Graph responses end-to-end. Cover at least one PASS case,
one FAIL case, and the skip path when data is missing:

```python
def test_pass_all_have_mfa():
    ctx = TenantContext(users=[
        User(id="u1", display_name="Alice", registered_auth_methods=["fido2"]),
    ])
    findings = UserNoMfaMethods().execute(ctx)
    assert findings[0].status == Status.PASS


def test_fail_user_without_methods():
    ctx = TenantContext(users=[
        User(id="u1", display_name="Alice", registered_auth_methods=[]),
    ])
    findings = UserNoMfaMethods().execute(ctx)
    assert findings[0].status == Status.FAIL
    assert findings[0].resource_id == "u1"


def test_skip_no_user_data():
    ctx = TenantContext(users=[])
    findings = UserNoMfaMethods().execute(ctx)
    assert findings[0].status == Status.SKIPPED_PERMISSION
```

## 5. Wire into the scan (only if new data is needed)

If your check needs a Graph endpoint EntraLint isn't already calling, add
the fetch in [`src/entralint/cli/commands/scan.py`](../src/entralint/cli/commands/scan.py)
and expose the parsed data on `TenantContext`
([`src/entralint/core/context.py`](../src/entralint/core/context.py)).
Existing checks mostly use the data already collected — most new checks
won't need to touch `scan.py`.

## 6. Verify

```powershell
# Lint & type-check
ruff check src tests
mypy src

# Run the new tests
pytest tests/unit/checks/test_<check_slug>.py -v

# Confirm discovery works
python -m entralint list-checks | Select-String <check_id>
```

If the check doesn't show up in `list-checks`, double-check that:

1. `__init__.py` exists in the check directory (even if empty).
2. `_load_metadata()` reads the JSON file correctly.
3. The class inherits from `BaseCheck` and is importable.

The engine will log a warning at `--debug` level if a check class fails
to instantiate.
