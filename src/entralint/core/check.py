"""Core check framework: BaseCheck, Finding, Severity, Status."""

from __future__ import annotations

import abc
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from entralint.core.context import TenantContext


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Status(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIPPED_LICENSE = "SKIPPED_LICENSE"
    SKIPPED_PERMISSION = "SKIPPED_PERMISSION"
    SKIPPED_DEPENDENCY = "SKIPPED_DEPENDENCY"
    ERROR = "ERROR"


class Remediation(BaseModel):
    recommendation: str
    url: str = ""


class FrameworkMapping(BaseModel):
    """Maps a check to one or more compliance framework controls."""

    framework: str
    controls: list[str]
    verified: bool = False
    source: str = ""


class CheckMetadata(BaseModel):
    check_id: str
    check_version: str = "1.0.0"
    check_title: str
    service_name: str
    severity: Severity
    resource_type: str
    description: str
    risk: str = ""
    remediation: Remediation = Field(default_factory=lambda: Remediation(recommendation=""))
    frameworks: list[FrameworkMapping] = Field(default_factory=list)
    graph_api_endpoints: list[str] = Field(default_factory=list)
    required_permissions: list[str] = Field(default_factory=list)
    required_license: str | None = None
    depends_on: list[str] = Field(default_factory=list)
    source_notes: str = ""


class Finding(BaseModel):
    check_id: str
    check_version: str = "1.0.0"
    status: Status
    severity: Severity = Severity.MEDIUM
    resource_type: str = ""
    resource_id: str = ""
    title: str = ""
    description: str = ""
    remediation: str = ""
    frameworks: list[FrameworkMapping] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)


class BaseCheck(abc.ABC):
    """Base class for all security checks."""

    metadata: CheckMetadata

    def __init__(self, metadata: CheckMetadata) -> None:
        self.metadata = metadata

    @abc.abstractmethod
    def execute(self, context: TenantContext) -> list[Finding]:
        """Run this check against with the tenant data and return findings."""
        ...

    def skip(self, reason: str, status: Status = Status.SKIPPED_PERMISSION) -> list[Finding]:
        """Return a single skipped finding for this check."""
        return [
            Finding(
                check_id=self.metadata.check_id,
                check_version=self.metadata.check_version,
                status=status,
                severity=self.metadata.severity,
                resource_type=self.metadata.resource_type,
                title=f"Check skipped: {self.metadata.check_title}",
                description=reason,
            )
        ]
