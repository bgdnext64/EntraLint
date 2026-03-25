"""TenantContext: holds cached Graph API data shared across checks."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from entralint.core.models import (
    Application,
    AppRoleAssignment,
    ConditionalAccessPolicy,
    DirectoryRoleAssignment,
    Organization,
    ServicePrincipal,
    User,
)


class TenantContext(BaseModel):
    """Holds all Graph API data for a single tenant, shared across checks."""

    tenant_id: str = ""
    tenant_display_name: str = ""

    # Organization
    organization: Organization = Field(default_factory=Organization)

    # Conditional Access
    conditional_access_policies: list[ConditionalAccessPolicy] = Field(default_factory=list)

    # Users
    users: list[User] = Field(default_factory=list)

    # Applications
    applications: list[Application] = Field(default_factory=list)

    # Service Principals
    service_principals: list[ServicePrincipal] = Field(default_factory=list)

    # Role Assignments
    role_assignments: list[DirectoryRoleAssignment] = Field(default_factory=list)

    # App role assignments (granted application permissions on SPs)
    app_role_assignments: list[AppRoleAssignment] = Field(default_factory=list)

    # Delegated permission grants (raw dicts for now)
    oauth2_permission_grants: list[dict[str, Any]] = Field(default_factory=list)

    # Policies (raw dicts until we model them fully)
    security_defaults_policy: dict[str, Any] = Field(default_factory=dict)
    authentication_methods_policy: dict[str, Any] = Field(default_factory=dict)
    authorization_policy: dict[str, Any] = Field(default_factory=dict)
    cross_tenant_access_policy: dict[str, Any] = Field(default_factory=dict)

    # Computed intermediate results shared between dependent checks
    computed: dict[str, Any] = Field(default_factory=dict)

    # Granted permissions (populated during pre-scan validation)
    granted_permissions: set[str] = Field(default_factory=set)

    # Detected license tier
    license_tier: str = "free"  # "free", "p1", "p2"
