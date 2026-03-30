"""Tests for batch 9 checks (user_009, app_008-009, sp_008-009, org_007-009, ca_014)."""

from entralint.checks.applications.app_already_expired_creds.app_already_expired_creds import (
    AppAlreadyExpiredCreds,
)
from entralint.checks.applications.app_excessive_delegated_perms import (
    app_excessive_delegated_perms as _deleg_perms_mod,
)
from entralint.checks.conditional_access.ca_no_admin_sign_in_frequency import (
    ca_no_admin_sign_in_frequency as _admin_sif_mod,
)
from entralint.checks.organization.org_cross_tenant_device_trust import (
    org_cross_tenant_device_trust as _device_trust_mod,
)
from entralint.checks.organization.org_cross_tenant_mfa_trust.org_cross_tenant_mfa_trust import (
    OrgCrossTenantMfaTrust,
)
from entralint.checks.organization.org_users_create_apps.org_users_create_apps import (
    OrgUsersCreateApps,
)
from entralint.checks.service_principals.sp_dual_credential_type.sp_dual_credential_type import (
    SpDualCredentialType,
)
from entralint.checks.service_principals.sp_expired_credentials.sp_expired_credentials import (
    SpExpiredCredentials,
)
from entralint.checks.users.user_disabled_with_roles.user_disabled_with_roles import (
    UserDisabledWithRoles,
)
from entralint.core.check import Status
from entralint.core.context import TenantContext
from entralint.core.models import (
    Application,
    ConditionalAccessConditions,
    ConditionalAccessConditionUsers,
    ConditionalAccessPolicy,
    ConditionalAccessSessionControls,
    DirectoryRoleAssignment,
    KeyCredential,
    PasswordCredential,
    RequiredResourceAccess,
    ResourceAccess,
    ServicePrincipal,
    User,
)

AppExcessiveDelegatedPerms = _deleg_perms_mod.AppExcessiveDelegatedPerms
CaNoAdminSignInFrequency = _admin_sif_mod.CaNoAdminSignInFrequency
OrgCrossTenantDeviceTrust = _device_trust_mod.OrgCrossTenantDeviceTrust

# ── user_009: Disabled users with roles ──────────────────────


def test_user009_pass_no_disabled_with_roles():
    users = [
        User(id="u1", account_enabled=False, display_name="Disabled"),
        User(id="u2", account_enabled=True, display_name="Active"),
    ]
    ras = [
        DirectoryRoleAssignment(id="r1", principal_id="u2", role_definition_id="some-role"),
    ]
    ctx = TenantContext(users=users, role_assignments=ras)
    assert UserDisabledWithRoles().execute(ctx)[0].status == Status.PASS


def test_user009_fail_disabled_has_role():
    users = [
        User(id="u1", account_enabled=False, display_name="Disabled Admin"),
    ]
    ras = [
        DirectoryRoleAssignment(id="r1", principal_id="u1", role_definition_id="some-role"),
    ]
    ctx = TenantContext(users=users, role_assignments=ras)
    findings = UserDisabledWithRoles().execute(ctx)
    assert findings[0].status == Status.FAIL
    assert "Disabled Admin" in findings[0].description


def test_user009_skip_no_data():
    ctx = TenantContext()
    assert UserDisabledWithRoles().execute(ctx)[0].status == Status.SKIPPED_PERMISSION


# ── app_008: Already-expired credentials ─────────────────────


def test_app008_pass_no_expired():
    app = Application(
        id="a1",
        display_name="Fresh",
        password_credentials=[
            PasswordCredential(key_id="k1", end_date_time="2099-12-31T00:00:00Z"),
        ],
    )
    ctx = TenantContext(applications=[app])
    assert AppAlreadyExpiredCreds().execute(ctx)[0].status == Status.PASS


def test_app008_fail_expired_password():
    app = Application(
        id="a1",
        display_name="Stale App",
        password_credentials=[
            PasswordCredential(key_id="k1", end_date_time="2020-01-01T00:00:00Z"),
        ],
    )
    ctx = TenantContext(applications=[app])
    findings = AppAlreadyExpiredCreds().execute(ctx)
    assert findings[0].status == Status.FAIL
    assert "Stale App" in findings[0].title


def test_app008_fail_expired_cert():
    app = Application(
        id="a1",
        display_name="Old Cert App",
        key_credentials=[
            KeyCredential(key_id="k1", end_date_time="2020-06-01T00:00:00Z"),
        ],
    )
    ctx = TenantContext(applications=[app])
    assert AppAlreadyExpiredCreds().execute(ctx)[0].status == Status.FAIL


def test_app008_pass_no_creds():
    app = Application(id="a1", display_name="No Creds")
    ctx = TenantContext(applications=[app])
    assert AppAlreadyExpiredCreds().execute(ctx)[0].status == Status.PASS


# ── app_009: Excessive delegated perms ───────────────────────


def test_app009_pass_few_scopes():
    app = Application(
        id="a1",
        display_name="Simple App",
        required_resource_access=[
            RequiredResourceAccess(
                resource_app_id="00000003-0000-0000-c000-000000000000",
                resource_access=[ResourceAccess(id=f"scope-{i}", type="Scope") for i in range(3)],
            )
        ],
    )
    ctx = TenantContext(applications=[app])
    assert AppExcessiveDelegatedPerms().execute(ctx)[0].status == Status.PASS


def test_app009_fail_many_scopes():
    app = Application(
        id="a1",
        display_name="Greedy App",
        required_resource_access=[
            RequiredResourceAccess(
                resource_app_id="00000003-0000-0000-c000-000000000000",
                resource_access=[ResourceAccess(id=f"scope-{i}", type="Scope") for i in range(15)],
            )
        ],
    )
    ctx = TenantContext(applications=[app])
    findings = AppExcessiveDelegatedPerms().execute(ctx)
    assert findings[0].status == Status.FAIL
    assert "15" in findings[0].title


def test_app009_pass_app_perms_not_delegated():
    app = Application(
        id="a1",
        display_name="App-Only",
        required_resource_access=[
            RequiredResourceAccess(
                resource_app_id="00000003-0000-0000-c000-000000000000",
                resource_access=[ResourceAccess(id=f"role-{i}", type="Role") for i in range(15)],
            )
        ],
    )
    ctx = TenantContext(applications=[app])
    assert AppExcessiveDelegatedPerms().execute(ctx)[0].status == Status.PASS


# ── sp_008: Expired SP credentials ──────────────────────────


def test_sp008_pass_valid():
    sp = ServicePrincipal(
        id="sp1",
        display_name="Valid SP",
        password_credentials=[
            PasswordCredential(key_id="k1", end_date_time="2099-01-01T00:00:00Z"),
        ],
    )
    ctx = TenantContext(service_principals=[sp])
    assert SpExpiredCredentials().execute(ctx)[0].status == Status.PASS


def test_sp008_fail_expired():
    sp = ServicePrincipal(
        id="sp1",
        display_name="Old SP",
        password_credentials=[
            PasswordCredential(key_id="k1", end_date_time="2020-01-01T00:00:00Z"),
        ],
    )
    ctx = TenantContext(service_principals=[sp])
    assert SpExpiredCredentials().execute(ctx)[0].status == Status.FAIL


def test_sp008_pass_no_creds():
    sp = ServicePrincipal(id="sp1", display_name="NoCreds SP")
    ctx = TenantContext(service_principals=[sp])
    assert SpExpiredCredentials().execute(ctx)[0].status == Status.PASS


# ── sp_009: Dual credential type ────────────────────────────


def test_sp009_pass_certs_only():
    sp = ServicePrincipal(
        id="sp1",
        display_name="Cert SP",
        key_credentials=[KeyCredential(key_id="k1")],
    )
    ctx = TenantContext(service_principals=[sp])
    assert SpDualCredentialType().execute(ctx)[0].status == Status.PASS


def test_sp009_fail_both_types():
    sp = ServicePrincipal(
        id="sp1",
        display_name="Dual SP",
        password_credentials=[PasswordCredential(key_id="p1")],
        key_credentials=[KeyCredential(key_id="k1")],
    )
    ctx = TenantContext(service_principals=[sp])
    findings = SpDualCredentialType().execute(ctx)
    assert findings[0].status == Status.FAIL
    assert "Dual SP" in findings[0].title


def test_sp009_pass_passwords_only():
    sp = ServicePrincipal(
        id="sp1",
        display_name="Secret SP",
        password_credentials=[PasswordCredential(key_id="p1")],
    )
    ctx = TenantContext(service_principals=[sp])
    assert SpDualCredentialType().execute(ctx)[0].status == Status.PASS


# ── org_007: Cross-tenant MFA trust ─────────────────────────


def test_org007_pass_not_trusted():
    policy = {"inboundTrust": {"isMfaAccepted": False}}
    ctx = TenantContext(cross_tenant_access_policy=policy)
    assert OrgCrossTenantMfaTrust().execute(ctx)[0].status == Status.PASS


def test_org007_fail_trusted():
    policy = {"inboundTrust": {"isMfaAccepted": True}}
    ctx = TenantContext(cross_tenant_access_policy=policy)
    assert OrgCrossTenantMfaTrust().execute(ctx)[0].status == Status.FAIL


def test_org007_pass_no_inbound_trust():
    policy = {"someOtherKey": {}}
    ctx = TenantContext(cross_tenant_access_policy=policy)
    assert OrgCrossTenantMfaTrust().execute(ctx)[0].status == Status.PASS


# ── org_008: Cross-tenant device trust ───────────────────────


def test_org008_pass_not_trusted():
    policy = {
        "inboundTrust": {
            "isCompliantDeviceAccepted": False,
            "isHybridAzureADJoinedDeviceAccepted": False,
        }
    }
    ctx = TenantContext(cross_tenant_access_policy=policy)
    assert OrgCrossTenantDeviceTrust().execute(ctx)[0].status == Status.PASS


def test_org008_fail_compliant_trusted():
    policy = {
        "inboundTrust": {
            "isCompliantDeviceAccepted": True,
            "isHybridAzureADJoinedDeviceAccepted": False,
        }
    }
    ctx = TenantContext(cross_tenant_access_policy=policy)
    assert OrgCrossTenantDeviceTrust().execute(ctx)[0].status == Status.FAIL


def test_org008_fail_hybrid_trusted():
    policy = {
        "inboundTrust": {
            "isCompliantDeviceAccepted": False,
            "isHybridAzureADJoinedDeviceAccepted": True,
        }
    }
    ctx = TenantContext(cross_tenant_access_policy=policy)
    assert OrgCrossTenantDeviceTrust().execute(ctx)[0].status == Status.FAIL


def test_org008_fail_both_trusted():
    policy = {
        "inboundTrust": {
            "isCompliantDeviceAccepted": True,
            "isHybridAzureADJoinedDeviceAccepted": True,
        }
    }
    ctx = TenantContext(cross_tenant_access_policy=policy)
    findings = OrgCrossTenantDeviceTrust().execute(ctx)
    assert findings[0].status == Status.FAIL
    assert "and" in findings[0].title


# ── org_009: Users can create apps ───────────────────────────


def test_org009_pass_restricted():
    policy = {"defaultUserRolePermissions": {"allowedToCreateApps": False}}
    ctx = TenantContext(authorization_policy=policy)
    assert OrgUsersCreateApps().execute(ctx)[0].status == Status.PASS


def test_org009_fail_allowed():
    policy = {"defaultUserRolePermissions": {"allowedToCreateApps": True}}
    ctx = TenantContext(authorization_policy=policy)
    assert OrgUsersCreateApps().execute(ctx)[0].status == Status.FAIL


def test_org009_fail_default():
    # When defaultUserRolePermissions missing, defaults to True
    policy = {"someOtherKey": {}}
    ctx = TenantContext(authorization_policy=policy)
    assert OrgUsersCreateApps().execute(ctx)[0].status == Status.FAIL


# ── ca_014: No admin sign-in frequency ───────────────────────

GA_ROLE = "62e90394-69f5-4237-9190-012177145e10"


def test_ca014_pass_frequency_set():
    p = ConditionalAccessPolicy(
        id="p1",
        display_name="Admin SIF",
        state="enabled",
        conditions=ConditionalAccessConditions(
            users=ConditionalAccessConditionUsers(include_roles=[GA_ROLE]),
        ),
        session_controls=ConditionalAccessSessionControls(
            sign_in_frequency={"isEnabled": True, "value": 4, "type": "hours"},
        ),
    )
    ctx = TenantContext(conditional_access_policies=[p])
    assert CaNoAdminSignInFrequency().execute(ctx)[0].status == Status.PASS


def test_ca014_pass_all_users_frequency():
    p = ConditionalAccessPolicy(
        id="p1",
        display_name="All SIF",
        state="enabled",
        conditions=ConditionalAccessConditions(
            users=ConditionalAccessConditionUsers(include_users=["All"]),
        ),
        session_controls=ConditionalAccessSessionControls(
            sign_in_frequency={"isEnabled": True, "value": 8, "type": "hours"},
        ),
    )
    ctx = TenantContext(conditional_access_policies=[p])
    assert CaNoAdminSignInFrequency().execute(ctx)[0].status == Status.PASS


def test_ca014_fail_no_frequency():
    p = ConditionalAccessPolicy(
        id="p1",
        display_name="Admin MFA",
        state="enabled",
        conditions=ConditionalAccessConditions(
            users=ConditionalAccessConditionUsers(include_roles=[GA_ROLE]),
        ),
    )
    ctx = TenantContext(conditional_access_policies=[p])
    assert CaNoAdminSignInFrequency().execute(ctx)[0].status == Status.FAIL


def test_ca014_fail_report_only_ignored():
    p = ConditionalAccessPolicy(
        id="p1",
        display_name="Admin SIF (Report)",
        state="enabledForReportingButNotEnforced",
        conditions=ConditionalAccessConditions(
            users=ConditionalAccessConditionUsers(include_roles=[GA_ROLE]),
        ),
        session_controls=ConditionalAccessSessionControls(
            sign_in_frequency={"isEnabled": True, "value": 4, "type": "hours"},
        ),
    )
    ctx = TenantContext(conditional_access_policies=[p])
    assert CaNoAdminSignInFrequency().execute(ctx)[0].status == Status.FAIL


def test_ca014_fail_no_policies():
    ctx = TenantContext(conditional_access_policies=[])
    assert CaNoAdminSignInFrequency().execute(ctx)[0].status == Status.SKIPPED_PERMISSION
