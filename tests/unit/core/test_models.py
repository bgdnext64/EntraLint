"""Tests for Pydantic Graph API models."""

from entralint.core.models import (
    Application,
    ConditionalAccessPolicy,
    User,
)


def test_conditional_access_policy_from_graph_json() -> None:
    raw = {
        "id": "policy-1",
        "displayName": "Require MFA for all users",
        "state": "enabled",
        "conditions": {
            "users": {"includeUsers": ["All"], "excludeUsers": []},
            "applications": {"includeApplications": ["All"]},
            "clientAppTypes": ["browser", "mobileAppsAndDesktopClients"],
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["mfa"],
        },
    }
    policy = ConditionalAccessPolicy.model_validate(raw)
    assert policy.state == "enabled"
    assert policy.display_name == "Require MFA for all users"
    assert "All" in policy.conditions.users.include_users
    assert policy.grant_controls is not None
    assert "mfa" in policy.grant_controls.built_in_controls


def test_user_from_graph_json() -> None:
    raw = {
        "id": "user-1",
        "displayName": "Alice",
        "userPrincipalName": "alice@contoso.com",
        "accountEnabled": True,
        "userType": "Member",
    }
    user = User.model_validate(raw)
    assert user.display_name == "Alice"
    assert user.user_type == "Member"


def test_application_with_credentials() -> None:
    raw = {
        "id": "app-1",
        "displayName": "My App",
        "appId": "abc-123",
        "signInAudience": "AzureADMyOrg",
        "passwordCredentials": [
            {"keyId": "key-1", "displayName": "secret1", "endDateTime": "2026-06-01T00:00:00Z"}
        ],
    }
    app = Application.model_validate(raw)
    assert len(app.password_credentials) == 1
    assert app.password_credentials[0].end_date_time == "2026-06-01T00:00:00Z"
