"""Pydantic models for Microsoft Graph API responses."""

from __future__ import annotations

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
    owners: list[dict[str, str]] = Field(default_factory=list)

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

    model_config = {"populate_by_name": True}


class DirectoryRoleAssignment(BaseModel):
    id: str = ""
    principal_id: str = Field(default="", alias="principalId")
    role_definition_id: str = Field(default="", alias="roleDefinitionId")
    directory_scope_id: str = Field(default="/", alias="directoryScopeId")
    principal: dict[str, str] | None = None
    role_definition: dict[str, str] | None = Field(
        default=None, alias="roleDefinition"
    )

    model_config = {"populate_by_name": True}


class Organization(BaseModel):
    id: str = ""
    display_name: str = Field(default="", alias="displayName")
    verified_domains: list[dict[str, str]] = Field(
        default_factory=list, alias="verifiedDomains"
    )

    model_config = {"populate_by_name": True}
