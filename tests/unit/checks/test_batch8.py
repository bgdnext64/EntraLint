"""Tests for batch 8 checks (auth_007-010, role_007-010, user_007-008)."""

from datetime import UTC

from entralint.core.check import Status
from entralint.core.context import TenantContext
from entralint.core.models import (
    ConditionalAccessConditions,
    ConditionalAccessConditionUsers,
    ConditionalAccessPolicy,
    DirectoryRoleAssignment,
    User,
)

# ── auth_007: FIDO2 not enabled ────────────────────────────


def test_auth007_pass_fido2_enabled():
    from entralint.checks.authentication.auth_fido2_not_enabled.auth_fido2_not_enabled import (
        AuthFido2NotEnabled,
    )

    policy = {
        "authenticationMethodConfigurations": [
            {"id": "Fido2", "state": "enabled"}
        ]
    }
    ctx = TenantContext(authentication_methods_policy=policy)
    assert AuthFido2NotEnabled().execute(ctx)[0].status == Status.PASS


def test_auth007_fail_fido2_disabled():
    from entralint.checks.authentication.auth_fido2_not_enabled.auth_fido2_not_enabled import (
        AuthFido2NotEnabled,
    )

    policy = {
        "authenticationMethodConfigurations": [
            {"id": "Fido2", "state": "disabled"}
        ]
    }
    ctx = TenantContext(authentication_methods_policy=policy)
    assert AuthFido2NotEnabled().execute(ctx)[0].status == Status.FAIL


def test_auth007_fail_fido2_missing():
    from entralint.checks.authentication.auth_fido2_not_enabled.auth_fido2_not_enabled import (
        AuthFido2NotEnabled,
    )

    policy = {"authenticationMethodConfigurations": []}
    ctx = TenantContext(authentication_methods_policy=policy)
    assert AuthFido2NotEnabled().execute(ctx)[0].status == Status.FAIL


def test_auth007_skip_no_policy():
    from entralint.checks.authentication.auth_fido2_not_enabled.auth_fido2_not_enabled import (
        AuthFido2NotEnabled,
    )

    ctx = TenantContext(authentication_methods_policy={})
    assert AuthFido2NotEnabled().execute(ctx)[0].status == Status.SKIPPED_PERMISSION


# ── auth_008: TAP lifetime ──────────────────────────────────


def test_auth008_pass_tap_disabled():
    from entralint.checks.authentication.auth_tap_long_lifetime.auth_tap_long_lifetime import (
        AuthTapLongLifetime,
    )

    policy = {
        "authenticationMethodConfigurations": [
            {"id": "TemporaryAccessPass", "state": "disabled"}
        ]
    }
    ctx = TenantContext(authentication_methods_policy=policy)
    assert AuthTapLongLifetime().execute(ctx)[0].status == Status.PASS


def test_auth008_pass_short_lifetime():
    from entralint.checks.authentication.auth_tap_long_lifetime.auth_tap_long_lifetime import (
        AuthTapLongLifetime,
    )

    policy = {
        "authenticationMethodConfigurations": [
            {
                "id": "TemporaryAccessPass",
                "state": "enabled",
                "maximumLifetimeInMinutes": 60,
            }
        ]
    }
    ctx = TenantContext(authentication_methods_policy=policy)
    assert AuthTapLongLifetime().execute(ctx)[0].status == Status.PASS


def test_auth008_fail_long_lifetime():
    from entralint.checks.authentication.auth_tap_long_lifetime.auth_tap_long_lifetime import (
        AuthTapLongLifetime,
    )

    policy = {
        "authenticationMethodConfigurations": [
            {
                "id": "TemporaryAccessPass",
                "state": "enabled",
                "maximumLifetimeInMinutes": 1440,
            }
        ]
    }
    ctx = TenantContext(authentication_methods_policy=policy)
    findings = AuthTapLongLifetime().execute(ctx)
    assert findings[0].status == Status.FAIL
    assert "1440" in findings[0].title


def test_auth008_pass_not_configured():
    from entralint.checks.authentication.auth_tap_long_lifetime.auth_tap_long_lifetime import (
        AuthTapLongLifetime,
    )

    policy = {"authenticationMethodConfigurations": []}
    ctx = TenantContext(authentication_methods_policy=policy)
    assert AuthTapLongLifetime().execute(ctx)[0].status == Status.PASS


# ── auth_009: Email OTP ─────────────────────────────────────


def test_auth009_pass_disabled():
    from entralint.checks.authentication.auth_email_otp_enabled.auth_email_otp_enabled import (
        AuthEmailOtpEnabled,
    )

    policy = {
        "authenticationMethodConfigurations": [
            {"id": "Email", "state": "disabled"}
        ]
    }
    ctx = TenantContext(authentication_methods_policy=policy)
    assert AuthEmailOtpEnabled().execute(ctx)[0].status == Status.PASS


def test_auth009_fail_enabled():
    from entralint.checks.authentication.auth_email_otp_enabled.auth_email_otp_enabled import (
        AuthEmailOtpEnabled,
    )

    policy = {
        "authenticationMethodConfigurations": [
            {"id": "Email", "state": "enabled"}
        ]
    }
    ctx = TenantContext(authentication_methods_policy=policy)
    assert AuthEmailOtpEnabled().execute(ctx)[0].status == Status.FAIL


def test_auth009_pass_not_present():
    from entralint.checks.authentication.auth_email_otp_enabled.auth_email_otp_enabled import (
        AuthEmailOtpEnabled,
    )

    policy = {"authenticationMethodConfigurations": []}
    ctx = TenantContext(authentication_methods_policy=policy)
    assert AuthEmailOtpEnabled().execute(ctx)[0].status == Status.PASS


# ── auth_010: Certificate auth ──────────────────────────────


def test_auth010_pass_enabled():
    from entralint.checks.authentication.auth_certificate_not_enabled.auth_certificate_not_enabled import (
        AuthCertificateNotEnabled,
    )

    policy = {
        "authenticationMethodConfigurations": [
            {"id": "X509Certificate", "state": "enabled"}
        ]
    }
    ctx = TenantContext(authentication_methods_policy=policy)
    assert AuthCertificateNotEnabled().execute(ctx)[0].status == Status.PASS


def test_auth010_fail_disabled():
    from entralint.checks.authentication.auth_certificate_not_enabled.auth_certificate_not_enabled import (
        AuthCertificateNotEnabled,
    )

    policy = {
        "authenticationMethodConfigurations": [
            {"id": "X509Certificate", "state": "disabled"}
        ]
    }
    ctx = TenantContext(authentication_methods_policy=policy)
    assert AuthCertificateNotEnabled().execute(ctx)[0].status == Status.FAIL


def test_auth010_fail_missing():
    from entralint.checks.authentication.auth_certificate_not_enabled.auth_certificate_not_enabled import (
        AuthCertificateNotEnabled,
    )

    policy = {"authenticationMethodConfigurations": []}
    ctx = TenantContext(authentication_methods_policy=policy)
    assert AuthCertificateNotEnabled().execute(ctx)[0].status == Status.FAIL


# ── role_007: PRA excessive ─────────────────────────────────

PRA_ROLE = "e8611ab8-c189-46e8-94e1-60213ab1f814"


def test_role007_pass_two():
    from entralint.checks.privileged_roles.role_pra_excessive.role_pra_excessive import (
        RolePraExcessive,
    )

    ras = [
        DirectoryRoleAssignment(id=f"r{i}", principal_id=f"u{i}", role_definition_id=PRA_ROLE)
        for i in range(2)
    ]
    ctx = TenantContext(role_assignments=ras)
    assert RolePraExcessive().execute(ctx)[0].status == Status.PASS


def test_role007_fail_three():
    from entralint.checks.privileged_roles.role_pra_excessive.role_pra_excessive import (
        RolePraExcessive,
    )

    ras = [
        DirectoryRoleAssignment(id=f"r{i}", principal_id=f"u{i}", role_definition_id=PRA_ROLE)
        for i in range(3)
    ]
    ctx = TenantContext(role_assignments=ras)
    findings = RolePraExcessive().execute(ctx)
    assert findings[0].status == Status.FAIL
    assert "3 assignments" in findings[0].title


def test_role007_pass_only_other_roles():
    from entralint.checks.privileged_roles.role_pra_excessive.role_pra_excessive import (
        RolePraExcessive,
    )

    ras = [
        DirectoryRoleAssignment(id="r1", principal_id="u1", role_definition_id="other-role-id")
    ]
    ctx = TenantContext(role_assignments=ras)
    assert RolePraExcessive().execute(ctx)[0].status == Status.PASS


# ── role_008: Multiple high-priv roles ──────────────────────

GA_ROLE = "62e90394-69f5-4237-9190-012177145e10"
SEC_ADMIN_ROLE = "194ae4cb-b126-40b2-bd5b-6091b380977d"


def test_role008_pass_single_role():
    from entralint.checks.privileged_roles.role_multiple_high_priv.role_multiple_high_priv import (
        RoleMultipleHighPriv,
    )

    ras = [
        DirectoryRoleAssignment(id="r1", principal_id="u1", role_definition_id=GA_ROLE)
    ]
    ctx = TenantContext(role_assignments=ras)
    assert RoleMultipleHighPriv().execute(ctx)[0].status == Status.PASS


def test_role008_fail_two_high_priv():
    from entralint.checks.privileged_roles.role_multiple_high_priv.role_multiple_high_priv import (
        RoleMultipleHighPriv,
    )

    ras = [
        DirectoryRoleAssignment(
            id="r1", principal_id="u1", role_definition_id=GA_ROLE,
            principal={"displayName": "Admin User"},
        ),
        DirectoryRoleAssignment(
            id="r2", principal_id="u1", role_definition_id=SEC_ADMIN_ROLE,
            principal={"displayName": "Admin User"},
        ),
    ]
    ctx = TenantContext(role_assignments=ras)
    findings = RoleMultipleHighPriv().execute(ctx)
    assert findings[0].status == Status.FAIL
    assert "Admin User" in findings[0].title


def test_role008_pass_different_users():
    from entralint.checks.privileged_roles.role_multiple_high_priv.role_multiple_high_priv import (
        RoleMultipleHighPriv,
    )

    ras = [
        DirectoryRoleAssignment(id="r1", principal_id="u1", role_definition_id=GA_ROLE),
        DirectoryRoleAssignment(id="r2", principal_id="u2", role_definition_id=SEC_ADMIN_ROLE),
    ]
    ctx = TenantContext(role_assignments=ras)
    assert RoleMultipleHighPriv().execute(ctx)[0].status == Status.PASS


# ── role_009: App Admin excessive ────────────────────────────

APP_ADMIN_ROLE = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"


def test_role009_pass_five():
    from entralint.checks.privileged_roles.role_app_admin_excessive.role_app_admin_excessive import (
        RoleAppAdminExcessive,
    )

    ras = [
        DirectoryRoleAssignment(id=f"r{i}", principal_id=f"u{i}", role_definition_id=APP_ADMIN_ROLE)
        for i in range(5)
    ]
    ctx = TenantContext(role_assignments=ras)
    assert RoleAppAdminExcessive().execute(ctx)[0].status == Status.PASS


def test_role009_fail_six():
    from entralint.checks.privileged_roles.role_app_admin_excessive.role_app_admin_excessive import (
        RoleAppAdminExcessive,
    )

    ras = [
        DirectoryRoleAssignment(id=f"r{i}", principal_id=f"u{i}", role_definition_id=APP_ADMIN_ROLE)
        for i in range(6)
    ]
    ctx = TenantContext(role_assignments=ras)
    assert RoleAppAdminExcessive().execute(ctx)[0].status == Status.FAIL


# ── role_010: Cloud App Admin excessive ──────────────────────

CLOUD_APP_ROLE = "158c047a-c907-4556-b7ef-446551a6b5f7"


def test_role010_pass_five():
    from entralint.checks.privileged_roles.role_cloud_app_admin_excessive.role_cloud_app_admin_excessive import (
        RoleCloudAppAdminExcessive,
    )

    ras = [
        DirectoryRoleAssignment(id=f"r{i}", principal_id=f"u{i}", role_definition_id=CLOUD_APP_ROLE)
        for i in range(5)
    ]
    ctx = TenantContext(role_assignments=ras)
    assert RoleCloudAppAdminExcessive().execute(ctx)[0].status == Status.PASS


def test_role010_fail_six():
    from entralint.checks.privileged_roles.role_cloud_app_admin_excessive.role_cloud_app_admin_excessive import (
        RoleCloudAppAdminExcessive,
    )

    ras = [
        DirectoryRoleAssignment(id=f"r{i}", principal_id=f"u{i}", role_definition_id=CLOUD_APP_ROLE)
        for i in range(6)
    ]
    ctx = TenantContext(role_assignments=ras)
    assert RoleCloudAppAdminExcessive().execute(ctx)[0].status == Status.FAIL


# ── user_007: Guest risk policy ──────────────────────────────


def _risk_policy(
    *,
    state: str = "enabled",
    users: ConditionalAccessConditionUsers | None = None,
    sign_in_risk: list[str] | None = None,
    user_risk: list[str] | None = None,
) -> ConditionalAccessPolicy:
    u = users or ConditionalAccessConditionUsers()
    conds = ConditionalAccessConditions(
        users=u,
        sign_in_risk_levels=sign_in_risk or [],
        user_risk_levels=user_risk or [],
    )
    return ConditionalAccessPolicy(
        id="p1", display_name="Risk Policy", state=state, conditions=conds,
    )


def test_user007_pass_all_users():
    from entralint.checks.users.user_guest_risk_policy.user_guest_risk_policy import (
        UserGuestRiskPolicy,
    )

    p = _risk_policy(
        users=ConditionalAccessConditionUsers(include_users=["All"]),
        sign_in_risk=["high"],
    )
    ctx = TenantContext(conditional_access_policies=[p])
    assert UserGuestRiskPolicy().execute(ctx)[0].status == Status.PASS


def test_user007_pass_guests_targeted():
    from entralint.checks.users.user_guest_risk_policy.user_guest_risk_policy import (
        UserGuestRiskPolicy,
    )

    p = _risk_policy(
        users=ConditionalAccessConditionUsers(include_users=["GuestsOrExternalUsers"]),
        user_risk=["medium"],
    )
    ctx = TenantContext(conditional_access_policies=[p])
    assert UserGuestRiskPolicy().execute(ctx)[0].status == Status.PASS


def test_user007_fail_no_guest_in_risk():
    from entralint.checks.users.user_guest_risk_policy.user_guest_risk_policy import (
        UserGuestRiskPolicy,
    )

    p = _risk_policy(
        users=ConditionalAccessConditionUsers(include_users=["user1"]),
        sign_in_risk=["high"],
    )
    ctx = TenantContext(conditional_access_policies=[p])
    assert UserGuestRiskPolicy().execute(ctx)[0].status == Status.FAIL


def test_user007_fail_no_risk_policies():
    from entralint.checks.users.user_guest_risk_policy.user_guest_risk_policy import (
        UserGuestRiskPolicy,
    )

    p = ConditionalAccessPolicy(
        id="p1", display_name="MFA", state="enabled",
        conditions=ConditionalAccessConditions(
            users=ConditionalAccessConditionUsers(include_users=["All"]),
        ),
    )
    ctx = TenantContext(conditional_access_policies=[p])
    assert UserGuestRiskPolicy().execute(ctx)[0].status == Status.FAIL


# ── user_008: Stale guests ──────────────────────────────────


def test_user008_pass_no_guests():
    from entralint.checks.users.user_stale_guests.user_stale_guests import (
        UserStaleGuests,
    )

    ctx = TenantContext(users=[
        User(id="u1", user_type="Member", display_name="Member User"),
    ])
    assert UserStaleGuests().execute(ctx)[0].status == Status.PASS


def test_user008_fail_stale_guest():
    from entralint.checks.users.user_stale_guests.user_stale_guests import (
        UserStaleGuests,
    )

    ctx = TenantContext(users=[
        User(
            id="g1",
            user_type="Guest",
            display_name="Old Guest",
            created_date_time="2023-01-01T00:00:00Z",
            sign_in_activity={
                "lastSignInDateTime": "2023-06-01T00:00:00Z",
            },
        ),
    ])
    assert UserStaleGuests().execute(ctx)[0].status == Status.FAIL


def test_user008_pass_recent_guest():
    from datetime import datetime

    from entralint.checks.users.user_stale_guests.user_stale_guests import (
        UserStaleGuests,
    )

    recent = datetime.now(UTC).isoformat()
    ctx = TenantContext(users=[
        User(
            id="g1",
            user_type="Guest",
            display_name="Active Guest",
            sign_in_activity={"lastSignInDateTime": recent},
        ),
    ])
    assert UserStaleGuests().execute(ctx)[0].status == Status.PASS


def test_user008_fail_no_signin_old_creation():
    from entralint.checks.users.user_stale_guests.user_stale_guests import (
        UserStaleGuests,
    )

    ctx = TenantContext(users=[
        User(
            id="g1",
            user_type="Guest",
            display_name="Never Signed In",
            created_date_time="2022-01-01T00:00:00Z",
        ),
    ])
    assert UserStaleGuests().execute(ctx)[0].status == Status.FAIL
