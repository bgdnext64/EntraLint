"""Pydantic models for Microsoft Graph API responses."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ConditionalAccessConditionUsers(BaseModel):
    include_users: list[str] = Field(default_factory=list, alias="includeUsers")
    exclude_users: list[str] = Field(default_factory=list, alias="excludeUsers")
    include_groups: list[str] = Field(default_factory=list, alias="includeGroups")
    exclude_groups: list[str] = Field(default_factory=list, alias="excludeGroups")
    include_roles: list[str] = Field(default_factory=list, alias="includeRoles")
    exclude_roles: list[str] = Field(default_factory=list, alias="excludeRoles")

    model_config = {"populate_by_name": True}


class ConditionalAccessConditionApps(BaseModel):
    include_applications: list[str] = Field(
        default_factory=list, alias="includeApplications"
    )
    exclude_applications: list[str] = Field(
        default_factory=list, alias="excludeApplications"
    )

    model_config = {"populate_by_name": True}


class ConditionalAccessConditions(BaseModel):
    users: ConditionalAccessConditionUsers = Field(
        default_factory=ConditionalAccessConditionUsers
    )
    applications: ConditionalAccessConditionApps = Field(
        default_factory=ConditionalAccessConditionApps
    )
    client_app_types: list[str] = Field(default_factory=list, alias="clientAppTypes")
    sign_in_risk_levels: list[str] = Field(
        default_factory=list, alias="signInRiskLevels"
    )
    user_risk_levels: list[str] = Field(
        default_factory=list, alias="userRiskLevels"
    )

    model_config = {"populate_by_name": True}


class ConditionalAccessGrantControls(BaseModel):
    operator: str = "OR"
    built_in_controls: list[str] = Field(default_factory=list, alias="builtInControls")
    authentication_strength: dict[str, str] | None = Field(
        default=None, alias="authenticationStrength"
    )

    model_config = {"populate_by_name": True}


class ConditionalAccessSessionControls(BaseModel):
    persistent_browser: dict[str, str] | None = Field(
        default=None, alias="persistentBrowser"
    )
    sign_in_frequency: dict[str, str | int] | None = Field(
        default=None, alias="signInFrequency"
    )

    model_config = {"populate_by_name": True}


class ConditionalAccessPolicy(BaseModel):
    id: str = ""
    display_name: str = Field(default="", alias="displayName")
    state: str = "disabled"
    conditions: ConditionalAccessConditions = Field(
        default_factory=ConditionalAccessConditions
    )
    grant_controls: ConditionalAccessGrantControls | None = Field(
        default=None, alias="grantControls"
    )
    session_controls: ConditionalAccessSessionControls | None = Field(
        default=None, alias="sessionControls"
    )

    model_config = {"populate_by_name": True}


class PasswordCredential(BaseModel):
    key_id: str = Field(default="", alias="keyId")
    display_name: str | None = Field(default=None, alias="displayName")
    end_date_time: str | None = Field(default=None, alias="endDateTime")

    model_config = {"populate_by_name": True}


class KeyCredential(BaseModel):
    key_id: str = Field(default="", alias="keyId")
    display_name: str | None = Field(default=None, alias="displayName")
    end_date_time: str | None = Field(default=None, alias="endDateTime")
    credential_type: str = Field(default="", alias="type")

    model_config = {"populate_by_name": True}


class ResourceAccess(BaseModel):
    """A single permission entry within requiredResourceAccess."""

    id: str = ""
    type: str = ""  # "Role" (application) or "Scope" (delegated)

    model_config = {"populate_by_name": True}


class RequiredResourceAccess(BaseModel):
    """Permissions an app declares it needs from a resource API."""

    resource_app_id: str = Field(default="", alias="resourceAppId")
    resource_access: list[ResourceAccess] = Field(
        default_factory=list, alias="resourceAccess"
    )

    model_config = {"populate_by_name": True}


class AppRoleAssignment(BaseModel):
    """A granted application permission on a service principal."""

    id: str = ""
    app_role_id: str = Field(default="", alias="appRoleId")
    principal_display_name: str = Field(default="", alias="principalDisplayName")
    principal_id: str = Field(default="", alias="principalId")
    principal_type: str = Field(default="", alias="principalType")
    resource_display_name: str = Field(default="", alias="resourceDisplayName")
    resource_id: str = Field(default="", alias="resourceId")

    model_config = {"populate_by_name": True}


class Application(BaseModel):
    id: str = ""
    display_name: str = Field(default="", alias="displayName")
    app_id: str = Field(default="", alias="appId")
    sign_in_audience: str = Field(default="", alias="signInAudience")
    password_credentials: list[PasswordCredential] = Field(
        default_factory=list, alias="passwordCredentials"
    )
    key_credentials: list[KeyCredential] = Field(
        default_factory=list, alias="keyCredentials"
    )
    owners: list[dict[str, Any]] = Field(default_factory=list)
    required_resource_access: list[RequiredResourceAccess] = Field(
        default_factory=list, alias="requiredResourceAccess"
    )

    model_config = {"populate_by_name": True}


class ServicePrincipal(BaseModel):
    id: str = ""
    display_name: str = Field(default="", alias="displayName")
    app_id: str = Field(default="", alias="appId")
    service_principal_type: str = Field(default="", alias="servicePrincipalType")
    account_enabled: bool = Field(default=True, alias="accountEnabled")
    password_credentials: list[PasswordCredential] = Field(
        default_factory=list, alias="passwordCredentials"
    )
    key_credentials: list[KeyCredential] = Field(
        default_factory=list, alias="keyCredentials"
    )

    model_config = {"populate_by_name": True}


class User(BaseModel):
    id: str = ""
    display_name: str = Field(default="", alias="displayName")
    user_principal_name: str = Field(default="", alias="userPrincipalName")
    account_enabled: bool = Field(default=True, alias="accountEnabled")
    user_type: str = Field(default="Member", alias="userType")
    created_date_time: str | None = Field(default=None, alias="createdDateTime")
    sign_in_activity: dict[str, Any] | None = Field(default=None, alias="signInActivity")

    model_config = {"populate_by_name": True}


class DirectoryRoleAssignment(BaseModel):
    id: str = ""
    principal_id: str = Field(default="", alias="principalId")
    role_definition_id: str = Field(default="", alias="roleDefinitionId")
    directory_scope_id: str = Field(default="/", alias="directoryScopeId")
    principal: dict[str, Any] | None = None
    role_definition: dict[str, Any] | None = Field(
        default=None, alias="roleDefinition"
    )

    model_config = {"populate_by_name": True}


class Organization(BaseModel):
    id: str = ""
    display_name: str = Field(default="", alias="displayName")
    verified_domains: list[dict[str, Any]] = Field(
        default_factory=list, alias="verifiedDomains"
    )

    model_config = {"populate_by_name": True}


# ---------------------------------------------------------------------------
# Agent Identity models (Microsoft Entra Agent ID — GA v1.0, March 2026)
# ---------------------------------------------------------------------------


class InheritablePermission(BaseModel):
    """Defines scopes a blueprint allows agent instances to inherit."""

    id: str = ""
    scope_collection_kind: str = Field(
        default="", alias="scopeCollectionKind"
    )
    # For enumeratedScopes, the specific scope values
    scopes: list[str] = Field(default_factory=list)
    resource_app_id: str = Field(default="", alias="resourceAppId")

    model_config = {"populate_by_name": True}


class AgentIdentityBlueprint(BaseModel):
    """Template defining an agent identity type (inherits application)."""

    id: str = ""
    app_id: str = Field(default="", alias="appId")
    display_name: str = Field(default="", alias="displayName")
    description: str | None = Field(default=None)
    sign_in_audience: str = Field(default="", alias="signInAudience")
    created_date_time: str | None = Field(
        default=None, alias="createdDateTime"
    )
    created_by_app_id: str | None = Field(
        default=None, alias="createdByAppId"
    )
    disabled_by_microsoft_status: str | None = Field(
        default=None, alias="disabledByMicrosoftStatus"
    )
    tags: list[str] = Field(default_factory=list)
    password_credentials: list[PasswordCredential] = Field(
        default_factory=list, alias="passwordCredentials"
    )
    key_credentials: list[KeyCredential] = Field(
        default_factory=list, alias="keyCredentials"
    )
    info: dict[str, Any] | None = None
    required_resource_access: list[RequiredResourceAccess] = Field(
        default_factory=list, alias="requiredResourceAccess"
    )
    # Populated via $expand or separate call
    owners: list[dict[str, Any]] = Field(default_factory=list)
    sponsors: list[dict[str, Any]] = Field(default_factory=list)
    inheritable_permissions: list[InheritablePermission] = Field(
        default_factory=list, alias="inheritablePermissions"
    )
    federated_identity_credentials: list[dict[str, Any]] = Field(
        default_factory=list, alias="federatedIdentityCredentials"
    )

    model_config = {"populate_by_name": True}


class AgentIdentityBlueprintPrincipal(BaseModel):
    """Tenant-specific instance of a blueprint (inherits servicePrincipal)."""

    id: str = ""
    app_id: str = Field(default="", alias="appId")
    display_name: str = Field(default="", alias="displayName")
    app_display_name: str = Field(default="", alias="appDisplayName")
    app_owner_organization_id: str | None = Field(
        default=None, alias="appOwnerOrganizationId"
    )
    account_enabled: bool = Field(default=True, alias="accountEnabled")
    service_principal_type: str = Field(
        default="", alias="servicePrincipalType"
    )
    tags: list[str] = Field(default_factory=list)
    owners: list[dict[str, Any]] = Field(default_factory=list)
    sponsors: list[dict[str, Any]] = Field(default_factory=list)
    app_role_assignments: list[AppRoleAssignment] = Field(
        default_factory=list, alias="appRoleAssignments"
    )

    model_config = {"populate_by_name": True}


class AgentIdentity(BaseModel):
    """Individual agent instance (inherits servicePrincipal)."""

    id: str = ""
    display_name: str = Field(default="", alias="displayName")
    app_id: str | None = Field(default=None, alias="appId")
    agent_identity_blueprint_id: str | None = Field(
        default=None, alias="agentIdentityBlueprintId"
    )
    account_enabled: bool = Field(default=True, alias="accountEnabled")
    service_principal_type: str = Field(
        default="ServiceIdentity", alias="servicePrincipalType"
    )
    created_by_app_id: str | None = Field(
        default=None, alias="createdByAppId"
    )
    created_date_time: str | None = Field(
        default=None, alias="createdDateTime"
    )
    disabled_by_microsoft_status: str | None = Field(
        default=None, alias="disabledByMicrosoftStatus"
    )
    tags: list[str] = Field(default_factory=list)
    owners: list[dict[str, Any]] = Field(default_factory=list)
    sponsors: list[dict[str, Any]] = Field(default_factory=list)
    app_role_assignments: list[AppRoleAssignment] = Field(
        default_factory=list, alias="appRoleAssignments"
    )
    oauth2_permission_grants: list[dict[str, Any]] = Field(
        default_factory=list, alias="oauth2PermissionGrants"
    )
    # Populated only when the tenant/Graph surface exposes sign-in telemetry
    # for agent service principals. When absent, staleness falls back to
    # createdDateTime.
    sign_in_activity: dict[str, Any] | None = Field(
        default=None, alias="signInActivity"
    )

    model_config = {"populate_by_name": True}
