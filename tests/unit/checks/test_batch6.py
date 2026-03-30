"""Tests for batch 6 checks (ca_009-012, role_004-005, user_004, app_006, auth_003, sp_006)."""

from datetime import UTC, datetime, timedelta

from entralint.core.check import Status
from entralint.core.context import TenantContext
from entralint.core.models import (
    Application,
    AppRoleAssignment,
    ConditionalAccessConditions,
    ConditionalAccessConditionUsers,
    ConditionalAccessGrantControls,
    ConditionalAccessPolicy,
    DirectoryRoleAssignment,
    PasswordCredential,
    ServicePrincipal,
    User,
)

# ── Helpers ──────────────────────────────────────────────────


def _ca(
    *,
    state: str = "enabled",
    users: ConditionalAccessConditionUsers | None = None,
    grant_controls: ConditionalAccessGrantControls | None = None,
    client_app_types: list[str] | None = None,
    include_roles: list[str] | None = None,
    session_controls=None,
) -> ConditionalAccessPolicy:
    u = users or ConditionalAccessConditionUsers()
    if include_roles:
        u = ConditionalAccessConditionUsers(
            include_roles=include_roles,
        )
    conds = ConditionalAccessConditions(
        users=u,
        client_app_types=client_app_types or [],
    )
    return ConditionalAccessPolicy(
        id="p1",
        display_name="Test Policy",
        state=state,
        conditions=conds,
        grant_controls=grant_controls,
        session_controls=session_controls,
    )


def _future(days: int) -> str:
    dt = datetime.now(tz=UTC) + timedelta(days=days)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _past(days: int) -> str:
    dt = datetime.now(tz=UTC) - timedelta(days=days)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ── ca_009: All report-only ──────────────────────────────────


def test_ca009_pass_one_enabled():
    from entralint.checks.conditional_access.ca_all_report_only.ca_all_report_only import (
        CaAllReportOnly,
    )

    ctx = TenantContext(
        conditional_access_policies=[_ca(state="enabled")]
    )
    assert CaAllReportOnly().execute(ctx)[0].status == Status.PASS


def test_ca009_fail_all_report_only():
    from entralint.checks.conditional_access.ca_all_report_only.ca_all_report_only import (
        CaAllReportOnly,
    )

    policies = [
        _ca(state="enabledForReportingButNotEnforced"),
        _ca(state="enabledForReportingButNotEnforced"),
    ]
    ctx = TenantContext(conditional_access_policies=policies)
    assert CaAllReportOnly().execute(ctx)[0].status == Status.FAIL


def test_ca009_fail_no_policies():
    from entralint.checks.conditional_access.ca_all_report_only.ca_all_report_only import (
        CaAllReportOnly,
    )

    ctx = TenantContext(conditional_access_policies=[])
    assert CaAllReportOnly().execute(ctx)[0].status == Status.FAIL


# ── ca_010: Device code flow ─────────────────────────────────


def test_ca010_pass_blocks_device_code():
    from entralint.checks.conditional_access.ca_device_code_flow.ca_device_code_flow import (
        CaDeviceCodeFlow,
    )

    p = _ca(
        client_app_types=["deviceCode"],
        grant_controls=ConditionalAccessGrantControls(
            built_in_controls=["block"]
        ),
    )
    ctx = TenantContext(conditional_access_policies=[p])
    assert CaDeviceCodeFlow().execute(ctx)[0].status == Status.PASS


def test_ca010_fail_no_block():
    from entralint.checks.conditional_access.ca_device_code_flow.ca_device_code_flow import (
        CaDeviceCodeFlow,
    )

    ctx = TenantContext(conditional_access_policies=[_ca()])
    assert CaDeviceCodeFlow().execute(ctx)[0].status == Status.FAIL


def test_ca010_fail_disabled():
    from entralint.checks.conditional_access.ca_device_code_flow.ca_device_code_flow import (
        CaDeviceCodeFlow,
    )

    p = _ca(
        state="disabled",
        client_app_types=["deviceCode"],
        grant_controls=ConditionalAccessGrantControls(
            built_in_controls=["block"]
        ),
    )
    ctx = TenantContext(conditional_access_policies=[p])
    assert CaDeviceCodeFlow().execute(ctx)[0].status == Status.FAIL


# ── ca_011: Excessive exclusions ─────────────────────────────


def test_ca011_pass_few_exclusions():
    from entralint.checks.conditional_access.ca_excessive_exclusions import (
        ca_excessive_exclusions,
    )

    CaExcessiveExclusions = ca_excessive_exclusions.CaExcessiveExclusions

    u = ConditionalAccessConditionUsers(
        exclude_users=["u1", "u2"],
    )
    ctx = TenantContext(
        conditional_access_policies=[_ca(users=u)]
    )
    assert CaExcessiveExclusions().execute(ctx)[0].status == Status.PASS


def test_ca011_fail_many_exclusions():
    from entralint.checks.conditional_access.ca_excessive_exclusions import (
        ca_excessive_exclusions,
    )

    CaExcessiveExclusions = ca_excessive_exclusions.CaExcessiveExclusions

    u = ConditionalAccessConditionUsers(
        exclude_users=[f"u{i}" for i in range(6)],
    )
    ctx = TenantContext(
        conditional_access_policies=[_ca(users=u)]
    )
    findings = CaExcessiveExclusions().execute(ctx)
    assert findings[0].status == Status.FAIL


def test_ca011_counts_groups_plus_users():
    from entralint.checks.conditional_access.ca_excessive_exclusions import (
        ca_excessive_exclusions,
    )

    CaExcessiveExclusions = ca_excessive_exclusions.CaExcessiveExclusions
    u = ConditionalAccessConditionUsers(
        exclude_users=["u1", "u2", "u3"],
        exclude_groups=["g1", "g2", "g3"],
    )
    ctx = TenantContext(
        conditional_access_policies=[_ca(users=u)]
    )
    # 6 total (3 users + 3 groups) > 5 threshold → FAIL
    result = CaExcessiveExclusions().execute(ctx)[0]
    assert result.status == Status.FAIL


# ── ca_012: Admin device compliance ──────────────────────────


def test_ca012_pass_compliant_device():
    from entralint.checks.conditional_access.ca_admin_device_compliance import (
        ca_admin_device_compliance,
    )

    CaAdminDeviceCompliance = ca_admin_device_compliance.CaAdminDeviceCompliance

    ga_id = "62e90394-69f5-4237-9190-012177145e10"
    p = _ca(
        include_roles=[ga_id],
        grant_controls=ConditionalAccessGrantControls(
            built_in_controls=["compliantDevice"]
        ),
    )
    ctx = TenantContext(conditional_access_policies=[p])
    assert CaAdminDeviceCompliance().execute(ctx)[0].status == Status.PASS


def test_ca012_fail_no_device_requirement():
    from entralint.checks.conditional_access.ca_admin_device_compliance import (
        ca_admin_device_compliance,
    )

    CaAdminDeviceCompliance = ca_admin_device_compliance.CaAdminDeviceCompliance

    ctx = TenantContext(conditional_access_policies=[_ca()])
    result = CaAdminDeviceCompliance().execute(ctx)[0]
    assert result.status == Status.FAIL


# ── role_004: Guest admins ───────────────────────────────────


def test_role004_pass_no_guests():
    from entralint.checks.privileged_roles.role_guest_admins.role_guest_admins import (
        RoleGuestAdmins,
    )

    ctx = TenantContext(
        users=[User(id="u1", user_type="Member")],
        role_assignments=[],
    )
    assert RoleGuestAdmins().execute(ctx)[0].status == Status.PASS


def test_role004_pass_guest_no_role():
    from entralint.checks.privileged_roles.role_guest_admins.role_guest_admins import (
        RoleGuestAdmins,
    )

    ctx = TenantContext(
        users=[User(id="u1", user_type="Guest")],
        role_assignments=[],
    )
    assert RoleGuestAdmins().execute(ctx)[0].status == Status.PASS


def test_role004_fail_guest_is_ga():
    from entralint.checks.privileged_roles.role_guest_admins.role_guest_admins import (
        RoleGuestAdmins,
    )

    ga_role = "62e90394-69f5-4237-9190-012177145e10"
    ctx = TenantContext(
        users=[User(id="g1", user_type="Guest")],
        role_assignments=[
            DirectoryRoleAssignment(
                principal_id="g1",
                role_definition_id=ga_role,
                principal={"displayName": "External Admin"},
            )
        ],
    )
    findings = RoleGuestAdmins().execute(ctx)
    assert findings[0].status == Status.FAIL
    assert "Guest" in findings[0].title


# ── role_005: SP directory roles ─────────────────────────────


def test_role005_pass_no_sp_roles():
    from entralint.checks.privileged_roles.role_sp_directory_roles.role_sp_directory_roles import (
        RoleSpDirectoryRoles,
    )

    ctx = TenantContext(
        service_principals=[ServicePrincipal(id="sp1")],
        role_assignments=[],
    )
    assert RoleSpDirectoryRoles().execute(ctx)[0].status == Status.PASS


def test_role005_fail_sp_has_ga():
    from entralint.checks.privileged_roles.role_sp_directory_roles.role_sp_directory_roles import (
        RoleSpDirectoryRoles,
    )

    ga_role = "62e90394-69f5-4237-9190-012177145e10"
    ctx = TenantContext(
        service_principals=[ServicePrincipal(id="sp1")],
        role_assignments=[
            DirectoryRoleAssignment(
                principal_id="sp1",
                role_definition_id=ga_role,
                principal={"displayName": "My App"},
            )
        ],
    )
    findings = RoleSpDirectoryRoles().execute(ctx)
    assert findings[0].status == Status.FAIL
    assert "Global Administrator" in findings[0].title


def test_role005_ignores_user_assignments():
    from entralint.checks.privileged_roles.role_sp_directory_roles.role_sp_directory_roles import (
        RoleSpDirectoryRoles,
    )

    ga_role = "62e90394-69f5-4237-9190-012177145e10"
    ctx = TenantContext(
        service_principals=[ServicePrincipal(id="sp1")],
        role_assignments=[
            DirectoryRoleAssignment(
                principal_id="user1",
                role_definition_id=ga_role,
            )
        ],
    )
    assert RoleSpDirectoryRoles().execute(ctx)[0].status == Status.PASS


# ── user_004: Guest access level ─────────────────────────────


def test_user004_pass_restricted():
    from entralint.checks.users.user_guest_access_level.user_guest_access_level import (
        UserGuestAccessLevel,
    )

    ctx = TenantContext(
        authorization_policy={
            "guestUserRoleId": "2af84b1e-32c8-42b7-82bc-daa82404023b",
        }
    )
    assert UserGuestAccessLevel().execute(ctx)[0].status == Status.PASS


def test_user004_fail_same_as_members():
    from entralint.checks.users.user_guest_access_level.user_guest_access_level import (
        UserGuestAccessLevel,
    )

    ctx = TenantContext(
        authorization_policy={
            "guestUserRoleId": "a0b1b346-4d3e-4e8b-98f8-753987be4970",
        }
    )
    assert UserGuestAccessLevel().execute(ctx)[0].status == Status.FAIL
    assert "same access" in UserGuestAccessLevel().execute(ctx)[0].title


def test_user004_fail_limited():
    from entralint.checks.users.user_guest_access_level.user_guest_access_level import (
        UserGuestAccessLevel,
    )

    ctx = TenantContext(
        authorization_policy={
            "guestUserRoleId": "10dae51f-b6af-4016-8d66-8c2a99b929b3",
        }
    )
    assert UserGuestAccessLevel().execute(ctx)[0].status == Status.FAIL


# ── app_006: Long-lived secrets ──────────────────────────────


def test_app006_pass_short_lived():
    from entralint.checks.applications.app_long_lived_secrets.app_long_lived_secrets import (
        AppLongLivedSecrets,
    )

    app = Application(
        id="a1",
        display_name="App1",
        password_credentials=[
            PasswordCredential(end_date_time=_future(180)),
        ],
    )
    ctx = TenantContext(applications=[app])
    assert AppLongLivedSecrets().execute(ctx)[0].status == Status.PASS


def test_app006_fail_long_lived():
    from entralint.checks.applications.app_long_lived_secrets.app_long_lived_secrets import (
        AppLongLivedSecrets,
    )

    app = Application(
        id="a1",
        display_name="LongApp",
        password_credentials=[
            PasswordCredential(end_date_time=_future(730)),
        ],
    )
    ctx = TenantContext(applications=[app])
    findings = AppLongLivedSecrets().execute(ctx)
    assert findings[0].status == Status.FAIL
    assert "Long-lived" in findings[0].title


def test_app006_fail_no_expiry():
    from entralint.checks.applications.app_long_lived_secrets.app_long_lived_secrets import (
        AppLongLivedSecrets,
    )

    app = Application(
        id="a1",
        display_name="NoExpiry",
        password_credentials=[
            PasswordCredential(end_date_time=None),
        ],
    )
    ctx = TenantContext(applications=[app])
    findings = AppLongLivedSecrets().execute(ctx)
    assert findings[0].status == Status.FAIL
    assert "no expiry" in findings[0].title


def test_app006_pass_no_secrets():
    from entralint.checks.applications.app_long_lived_secrets.app_long_lived_secrets import (
        AppLongLivedSecrets,
    )

    ctx = TenantContext(applications=[Application(id="a1")])
    assert AppLongLivedSecrets().execute(ctx)[0].status == Status.PASS


# ── auth_003: Banned passwords ───────────────────────────────


def test_auth003_pass_enabled():
    from entralint.checks.authentication.auth_banned_passwords.auth_banned_passwords import (
        AuthBannedPasswords,
    )

    ctx = TenantContext(
        authentication_methods_policy={
            "authenticationMethodConfigurations": [
                {"id": "password", "state": "enabled"},
            ]
        }
    )
    assert AuthBannedPasswords().execute(ctx)[0].status == Status.PASS


def test_auth003_pass_banned_check():
    from entralint.checks.authentication.auth_banned_passwords.auth_banned_passwords import (
        AuthBannedPasswords,
    )

    ctx = TenantContext(
        authentication_methods_policy={
            "enableBannedPasswordCheck": True,
        }
    )
    assert AuthBannedPasswords().execute(ctx)[0].status == Status.PASS


def test_auth003_fail_no_config():
    from entralint.checks.authentication.auth_banned_passwords.auth_banned_passwords import (
        AuthBannedPasswords,
    )

    ctx = TenantContext(authentication_methods_policy={})
    assert AuthBannedPasswords().execute(ctx)[0].status == Status.FAIL


# ── sp_006: Stale credentials ────────────────────────────────


def test_sp006_pass_sp_has_assignments():
    from entralint.checks.service_principals.sp_stale_credentials.sp_stale_credentials import (
        SpStaleCredentials,
    )

    sp = ServicePrincipal(
        id="sp1",
        display_name="Active SP",
        password_credentials=[
            PasswordCredential(end_date_time=_future(90)),
        ],
    )
    ctx = TenantContext(
        service_principals=[sp],
        app_role_assignments=[
            AppRoleAssignment(principal_id="sp1"),
        ],
    )
    assert SpStaleCredentials().execute(ctx)[0].status == Status.PASS


def test_sp006_fail_sp_no_assignments():
    from entralint.checks.service_principals.sp_stale_credentials.sp_stale_credentials import (
        SpStaleCredentials,
    )

    sp = ServicePrincipal(
        id="sp1",
        display_name="Orphan SP",
        password_credentials=[
            PasswordCredential(end_date_time=_future(90)),
        ],
    )
    ctx = TenantContext(service_principals=[sp])
    findings = SpStaleCredentials().execute(ctx)
    assert findings[0].status == Status.FAIL
    assert "unused" in findings[0].title.lower()


def test_sp006_pass_expired_creds():
    from entralint.checks.service_principals.sp_stale_credentials.sp_stale_credentials import (
        SpStaleCredentials,
    )

    sp = ServicePrincipal(
        id="sp1",
        display_name="Expired SP",
        password_credentials=[
            PasswordCredential(end_date_time=_past(30)),
        ],
    )
    ctx = TenantContext(service_principals=[sp])
    assert SpStaleCredentials().execute(ctx)[0].status == Status.PASS


def test_sp006_skips_managed_identity():
    from entralint.checks.service_principals.sp_stale_credentials.sp_stale_credentials import (
        SpStaleCredentials,
    )

    sp = ServicePrincipal(
        id="sp1",
        display_name="MI",
        service_principal_type="ManagedIdentity",
        password_credentials=[
            PasswordCredential(end_date_time=_future(90)),
        ],
    )
    ctx = TenantContext(service_principals=[sp])
    assert SpStaleCredentials().execute(ctx)[0].status == Status.PASS
