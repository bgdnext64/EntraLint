"""Check discovery, dependency resolution, and execution pipeline."""

from __future__ import annotations

import importlib
import importlib.util
import pkgutil
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from entralint.core.check import BaseCheck, Finding, Status

if TYPE_CHECKING:
    from entralint.core.context import TenantContext


# Well-known directories for user-supplied custom checks.
_USER_CUSTOM_DIR = Path.home() / ".entralint" / "custom_checks"
_PROJECT_CUSTOM_DIR = Path.cwd() / ".entralint" / "checks"


class CheckEngine:
    """Discovers, filters, orders, and executes security checks."""

    def __init__(
        self,
        checks_dirs: list[Path] | None = None,
        *,
        custom_checks_dirs: list[Path] | None = None,
    ) -> None:
        self._checks_dirs = checks_dirs or [
            Path(__file__).parent.parent / "checks",
        ]
        # Append default custom-check locations + any user-configured extras.
        extra: list[Path] = []
        for d in [_USER_CUSTOM_DIR, _PROJECT_CUSTOM_DIR]:
            if d.is_dir():
                extra.append(d)
        if custom_checks_dirs:
            for d in custom_checks_dirs:
                if d.is_dir() and d not in extra:
                    extra.append(d)
        self._custom_dirs = extra
        self._checks: list[BaseCheck] = []

    def discover(self) -> list[BaseCheck]:
        """Auto-discover all check classes from built-in and custom directories."""
        discovered: list[BaseCheck] = []
        seen_ids: set[str] = set()

        # Built-in checks (entralint package).
        for checks_dir in self._checks_dirs:
            if not checks_dir.exists():
                continue
            for check in self._discover_in_dir(checks_dir):
                if check.metadata.check_id not in seen_ids:
                    seen_ids.add(check.metadata.check_id)
                    discovered.append(check)

        # Custom / external checks.
        for custom_dir in self._custom_dirs:
            for check in self._discover_external_dir(custom_dir):
                if check.metadata.check_id not in seen_ids:
                    seen_ids.add(check.metadata.check_id)
                    discovered.append(check)

        self._checks = discovered
        return discovered

    def _discover_in_dir(self, checks_dir: Path) -> list[BaseCheck]:
        """Recursively discover checks in a directory tree."""
        found: list[BaseCheck] = []
        package_name = self._path_to_package(checks_dir)
        if package_name is None:
            return found

        try:
            package = importlib.import_module(package_name)
        except ImportError:
            return found

        for _importer, modname, _ispkg in pkgutil.walk_packages(
            package.__path__, prefix=package.__name__ + "."
        ):
            try:
                module = importlib.import_module(modname)
            except ImportError:
                continue

            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (
                    isinstance(attr, type)
                    and issubclass(attr, BaseCheck)
                    and attr is not BaseCheck
                    and hasattr(attr, "metadata")
                ):
                    try:
                        found.append(attr())
                    except TypeError:
                        try:
                            found.append(attr(metadata=attr.metadata))
                        except Exception:
                            continue

        return found

    @staticmethod
    def _discover_external_dir(checks_dir: Path) -> list[BaseCheck]:
        """Discover checks from a directory outside the entralint package.

        Loads each ``.py`` file as an ad-hoc module using
        ``importlib.util.spec_from_file_location`` so that custom checks
        don't need to live in the ``entralint`` namespace.
        """
        found: list[BaseCheck] = []
        if not checks_dir.is_dir():
            return found

        for py_file in sorted(checks_dir.rglob("*.py")):
            if py_file.name.startswith("_"):
                continue
            module_name = f"entralint_custom.{py_file.stem}_{id(py_file)}"
            spec = importlib.util.spec_from_file_location(module_name, py_file)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            try:
                spec.loader.exec_module(module)  # type: ignore[union-attr]
            except Exception:
                continue

            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (
                    isinstance(attr, type)
                    and issubclass(attr, BaseCheck)
                    and attr is not BaseCheck
                    and hasattr(attr, "metadata")
                ):
                    try:
                        found.append(attr())
                    except TypeError:
                        try:
                            found.append(attr(metadata=attr.metadata))
                        except Exception:
                            continue
        return found

    def _path_to_package(self, path: Path) -> str | None:
        """Convert a filesystem path to a Python package name."""
        parts = path.parts
        try:
            src_idx = parts.index("entralint")
            return ".".join(parts[src_idx:])
        except ValueError:
            return None

    def filter_checks(
        self,
        *,
        severity: list[str] | None = None,
        category: str | None = None,
        check_ids: list[str] | None = None,
        framework: str | None = None,
    ) -> list[BaseCheck]:
        """Filter discovered checks by user-selected criteria."""
        filtered = list(self._checks)

        if check_ids:
            ids_set = set(check_ids)
            filtered = [c for c in filtered if c.metadata.check_id in ids_set]

        if severity:
            sev_set = {s.upper() for s in severity}
            filtered = [c for c in filtered if c.metadata.severity.value in sev_set]

        if category:
            cat = category.lower()
            filtered = [c for c in filtered if c.metadata.service_name.lower() == cat]

        if framework:
            fw = framework.lower()
            filtered = [
                c
                for c in filtered
                if any(m.framework.lower() == fw for m in c.metadata.frameworks)
            ]

        self._checks = filtered
        return filtered

    def build_execution_order(self) -> list[BaseCheck]:
        """Topological sort of checks based on DependsOn metadata."""
        graph = {c.metadata.check_id: c for c in self._checks}
        visited: set[str] = set()
        order: list[BaseCheck] = []

        def visit(check_id: str) -> None:
            if check_id in visited:
                return
            visited.add(check_id)
            check = graph.get(check_id)
            if check is None:
                return
            for dep_id in check.metadata.depends_on:
                if dep_id in graph:
                    visit(dep_id)
            order.append(check)

        for check_id in graph:
            visit(check_id)

        self._checks = order
        return order

    def execute(self, context: TenantContext) -> list[Finding]:
        """Run all checks in order and return aggregated findings."""
        all_findings: list[Finding] = []
        failed_check_ids: set[str] = set()

        for check in self._checks:
            # Skip if a dependency failed
            unmet = [
                dep for dep in check.metadata.depends_on if dep in failed_check_ids
            ]
            if unmet:
                findings = check.skip(
                    reason=f"Prerequisite check(s) failed: {', '.join(unmet)}",
                    status=Status.SKIPPED_DEPENDENCY,
                )
                all_findings.extend(findings)
                continue

            # Skip if missing required permissions
            if check.metadata.required_permissions:
                missing = set(check.metadata.required_permissions) - context.granted_permissions
                if missing:
                    findings = check.skip(
                        reason=f"Missing permissions: {', '.join(sorted(missing))}",
                        status=Status.SKIPPED_PERMISSION,
                    )
                    all_findings.extend(findings)
                    continue

            # Execute the check
            try:
                findings = check.execute(context)
                for finding in findings:
                    if not finding.frameworks:
                        finding.frameworks = check.metadata.frameworks
                all_findings.extend(findings)

                # Track failures for dependency resolution
                if any(f.status == Status.FAIL for f in findings):
                    failed_check_ids.add(check.metadata.check_id)

            except Exception as exc:
                all_findings.append(
                    Finding(
                        check_id=check.metadata.check_id,
                        check_version=check.metadata.check_version,
                        status=Status.ERROR,
                        severity=check.metadata.severity,
                        title=f"Check error: {check.metadata.check_title}",
                        description=str(exc),
                    )
                )

        return all_findings
