"""Tests for batch 7 checks."""

from entralint.core.check import Status
from entralint.core.context import TenantContext
from entralint.core.models import (
    Application,
    ConditionalAccessConditions,
    ConditionalAccessConditionUsers,
    ConditionalAccessPolicy,
    DirectoryRoleAssignment,
    RequiredResourceAccess,
    ResourceAccess,
    User,
)

# ── Helpers ──────────────────────────────────────────────────


def _ca(
    *,
    state: str = "enabled",
    users: ConditionalAccessConditionUsers | None = None,
) -> ConditionalAccessPolicy:
    u = users or ConditionalAccessConditionUsers()
    conds = ConditionalAccessConditions(users=u)
    return ConditionalAccessPolicy(
        id="p1",
        display_name="Test Policy",
        state=state,
        conditions=conds,
    )


# ── ca_013: Guest not targeted ──────────────────────────────


def test_ca013_pass_targets_guests():
    from entralint.checks.conditional_access.ca_guest_not_targeted.ca_guest_not_targeted import (
        CaGuestNotTargeted,
    )

    u = ConditionalAccessConditionUsers(
        include_users=["GuestsOrExternalUsers"],
    )
    ctx = TenantContext(conditional_access_policies=[_ca(users=u)])
    assert CaGuestNotTargeted().execute(ctx)[0].status == Status.PASS


def test_ca013_pass_targets_all():
    from entralint.checks.conditional_access.ca_guest_not_targeted.ca_guest_not_targeted import (
        CaGuestNotTargeted,
    )

    u = ConditionalAccessConditionUsers(include_users=["All"])
    ctx = TenantContext(conditional_access_policies=[_ca(users=u)])
    assert CaGuestNotTargeted().execute(ctx)[0].status == Status.PASS


def test_ca013_fail_no_guest_targeting():
    from entralint.checks.conditional_access.ca_guest_not_targeted.ca_guest_not_targeted import (
        CaGuestNotTargeted,
    )

    u = ConditionalAccessConditionUsers(include_users=["user1"])
    ctx = TenantContext(conditional_access_policies=[_ca(users=u)])
    assert CaGuestNotTargeted().execute(ctx)[0].status == Status.FAIL


def test_ca013_fail_no_policies():
    from entralint.checks.conditional_access.ca_guest_not_targeted.ca_guest_not_targeted import (
        CaGuestNotTargeted,
    )

    ctx = TenantContext(conditional_access_policies=[])
    assert CaGuestNotTargeted().execute(ctx)[0].status == Status.FAIL


def test_ca013_ignores_report_only():
    from entralint.checks.conditional_access.ca_guest_not_targeted.ca_guest_not_targeted import (
        CaGuestNotTargeted,
    )

    u = ConditionalAccessConditionUsers(
        include_users=["GuestsOrExternalUsers"],
    )
    p = _ca(state="enabledForReportingButNotEnforced", users=u)
    ctx = TenantContext(conditional_access_policies=[p])
    assert CaGuestNotTargeted().execute(ctx)[0].status == Status.FAIL


# ── auth_004: Number matching ───────────────────────────────


def test_auth004_pass_enabled():
    from entralint.checks.authentication.auth_number_matching.auth_number_matching import (
        AuthNumberMatching,
    )

    policy = {
        "authenticationMethodConfigurations": [
            {
                "id": "MicrosoftAuthenticator",
                "state": "enabled",
                "featureSettings": {
                    "numberMatchingRequiredState": {
                        "state": "enabled"
                    }
                },
            }
        ]
    }
    ctx = TenantContext(authentication_methods_policy=policy)
    assert AuthNumberMatching().execute(ctx)[0].status == Status.PASS


def test_auth004_pass_default():
    from entralint.checks.authentication.auth_number_matching.auth_number_matching import (
        AuthNumberMatching,
    )

    policy = {
        "authenticationMethodConfigurations": [
            {
                "id": "MicrosoftAuthenticator",
                "state": "enabled",
                "featureSettings": {
                    "numberMatchingRequiredState": {
                        "state": "default"
                    }
                },
            }
        ]
    }
    ctx = TenantContext(authentication_methods_policy=policy)
    assert AuthNumberMatching().execute(ctx)[0].status == Status.PASS


def test_auth004_fail_disabled():
    from entralint.checks.authentication.auth_number_matching.auth_number_matching import (
        AuthNumberMatching,
    )

    policy = {
        "authenticationMethodConfigurations": [
            {
                "id": "MicrosoftAuthenticator",
                "state": "enabled",
                "featureSettings": {
                    "numberMatchingRequiredState": {
                        "state": "disabled"
                    }
                },
            }
        ]
    }
    ctx = TenantContext(authentication_methods_policy=policy)
    assert AuthNumberMatching().execute(ctx)[0].status == Status.FAIL


# ── auth_005: Software OATH ─────────────────────────────────


def test_auth005_pass_disabled():
    from entralint.checks.authentication.auth_software_oath.auth_software_oath import (
        AuthSoftwareOath,
    )

    policy = {
        "authenticationMethodConfigurations": [
            {"id": "SoftwareOath", "state": "disabled"}
        ]
    }
    ctx = TenantContext(authentication_methods_policy=policy)
    assert AuthSoftwareOath().execute(ctx)[0].status == Status.PASS


def test_auth005_fail_enabled():
    from entralint.checks.authentication.auth_software_oath.auth_software_oath import (
        AuthSoftwareOath,
    )

    policy = {
        "authenticationMethodConfigurations": [
            {"id": "SoftwareOath", "state": "enabled"}
        ]
    }
    ctx = TenantContext(authentication_methods_policy=policy)
    assert AuthSoftwareOath().execute(ctx)[0].status == Status.FAIL


def test_auth005_pass_not_configured():
    from entralint.checks.authentication.auth_software_oath.auth_software_oath import (
        AuthSoftwareOath,
    )

    policy = {"authenticationMethodConfigurations": []}
    ctx = TenantContext(authentication_methods_policy=policy)
    assert AuthSoftwareOath().execute(ctx)[0].status == Status.PASS


# ── auth_006: Trusted IPs ───────────────────────────────────


def test_auth006_pass_no_locations():
    from entralint.checks.authentication.auth_trusted_ips.auth_trusted_ips import (
        AuthTrustedIps,
    )

    ctx = TenantContext(named_locations=[])
    assert AuthTrustedIps().execute(ctx)[0].status == Status.PASS


def test_auth006_pass_untrusted():
    from entralint.checks.authentication.auth_trusted_ips.auth_trusted_ips import (
        AuthTrustedIps,
    )

    ctx = TenantContext(named_locations=[
        {"id": "loc1", "displayName": "Office", "isTrusted": False}
    ])
    assert AuthTrustedIps().execute(ctx)[0].status == Status.PASS


def test_auth006_fail_trusted():
    from entralint.checks.authentication.auth_trusted_ips.auth_trusted_ips import (
        AuthTrustedIps,
    )

    ctx = TenantContext(named_locations=[
        {"id": "loc1", "displayName": "Corp VPN", "isTrusted": True}
    ])
    findings = AuthTrustedIps().execute(ctx)
    assert findings[0].status == Status.FAIL
    assert "Corp VPN" in findings[0].title


def test_auth006_multiple_trusted():
    from entralint.checks.authentication.auth_trusted_ips.auth_trusted_ips import (
        AuthTrustedIps,
    )

    ctx = TenantContext(named_locations=[
        {"id": "l1", "displayName": "VPN", "isTrusted": True},
        {"id": "l2", "displayName": "Office", "isTrusted": False},
        {"id": "l3", "displayName": "Branch", "isTrusted": True},
    ])
    findings = AuthTrustedIps().execute(ctx)
    fail_count = sum(1 for f in findings if f.status == Status.FAIL)
    assert fail_count == 2


# ── org_006: Outbound cross-tenant ──────────────────────────


def test_org006_pass_restricted():
    from entralint.checks.organization.org_outbound_cross_tenant.org_outbound_cross_tenant import (
        OrgOutboundCrossTenant,
    )

    policy = {
        "b2bCollaborationOutbound": {
            "applications": {"accessType": "blocked"},
            "usersAndGroups": {"accessType": "blocked"},
        },
        "b2bDirectConnectOutbound": {
            "applications": {"accessType": "blocked"},
            "usersAndGroups": {"accessType": "blocked"},
        },
    }
    ctx = TenantContext(cross_tenant_access_policy=policy)
    assert OrgOutboundCrossTenant().execute(ctx)[0].status == Status.PASS


def test_org006_fail_collab_open():
    from entralint.checks.organization.org_outbound_cross_tenant.org_outbound_cross_tenant import (
        OrgOutboundCrossTenant,
    )

    policy = {
        "b2bCollaborationOutbound": {
            "applications": {"accessType": "allowed"},
            "usersAndGroups": {"accessType": "allowed"},
        },
        "b2bDirectConnectOutbound": {
            "applications": {"accessType": "blocked"},
            "usersAndGroups": {"accessType": "blocked"},
        },
    }
    ctx = TenantContext(cross_tenant_access_policy=policy)
    findings = OrgOutboundCrossTenant().execute(ctx)
    fail_count = sum(1 for f in findings if f.status == Status.FAIL)
    assert fail_count == 1


def test_org006_fail_both_open():
    from entralint.checks.organization.org_outbound_cross_tenant.org_outbound_cross_tenant import (
        OrgOutboundCrossTenant,
    )

    policy = {
        "b2bCollaborationOutbound": {
            "applications": {"accessType": "allowed"},
            "usersAndGroups": {"accessType": "allowed"},
        },
        "b2bDirectConnectOutbound": {
            "applications": {"accessType": "allowed"},
            "usersAndGroups": {"accessType": "allowed"},
        },
    }
    ctx = TenantContext(cross_tenant_access_policy=policy)
    findings = OrgOutboundCrossTenant().execute(ctx)
    fail_count = sum(1 for f in findings if f.status == Status.FAIL)
    assert fail_count == 2


# ── app_007: Priv owner escalation ──────────────────────────


def test_app007_pass_admin_owner():
    from entralint.checks.applications.app_priv_owner_escalation.app_priv_owner_escalation import (
        AppPrivOwnerEscalation,
    )

    ga_role = "62e90394-69f5-4237-9190-012177145e10"
    dangerous_perm = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"
    app = Application(
        id="a1",
        display_name="PrivApp",
        owners=[{"id": "admin1", "displayName": "Admin"}],
        required_resource_access=[
            RequiredResourceAccess(
                resource_app_id="00000003-0000-0000-c000-000000000000",
                resource_access=[
                    ResourceAccess(id=dangerous_perm, type="Role"),
                ],
            )
        ],
    )
    ra = DirectoryRoleAssignment(
        id="ra1",
        principal_id="admin1",
        role_definition_id=ga_role,
    )
    ctx = TenantContext(applications=[app], role_assignments=[ra])
    assert AppPrivOwnerEscalation().execute(ctx)[0].status == Status.PASS


def test_app007_fail_nonadmin_owner():
    from entralint.checks.applications.app_priv_owner_escalation.app_priv_owner_escalation import (
        AppPrivOwnerEscalation,
    )

    dangerous_perm = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"
    app = Application(
        id="a1",
        display_name="PrivApp",
        owners=[{"id": "user1", "displayName": "Regular User"}],
        required_resource_access=[
            RequiredResourceAccess(
                resource_app_id="00000003-0000-0000-c000-000000000000",
                resource_access=[
                    ResourceAccess(id=dangerous_perm, type="Role"),
                ],
            )
        ],
    )
    ctx = TenantContext(applications=[app], role_assignments=[])
    findings = AppPrivOwnerEscalation().execute(ctx)
    assert findings[0].status == Status.FAIL
    assert "Regular User" in findings[0].description


def test_app007_pass_no_dangerous_perms():
    from entralint.checks.applications.app_priv_owner_escalation.app_priv_owner_escalation import (
        AppPrivOwnerEscalation,
    )

    app = Application(
        id="a1",
        display_name="SafeApp",
        owners=[{"id": "user1", "displayName": "User"}],
        required_resource_access=[
            RequiredResourceAccess(
                resource_app_id="00000003-0000-0000-c000-000000000000",
                resource_access=[
                    ResourceAccess(
                        id="some-safe-perm-id", type="Role"
                    ),
                ],
            )
        ],
    )
    ctx = TenantContext(applications=[app], role_assignments=[])
    assert AppPrivOwnerEscalation().execute(ctx)[0].status == Status.PASS


# ── sp_007: Broad delegated perms ────────────────────────────


def test_sp007_pass_few_broad():
    from entralint.checks.service_principals.sp_broad_delegated_perms import (
        sp_broad_delegated_perms,
    )

    SpBroadDelegatedPerms = sp_broad_delegated_perms.SpBroadDelegatedPerms

    grants = [
        {
            "clientId": "sp1",
            "consentType": "AllPrincipals",
            "scope": "mail.read User.Read",
        }
    ]
    ctx = TenantContext(oauth2_permission_grants=grants)
    assert SpBroadDelegatedPerms().execute(ctx)[0].status == Status.PASS


def test_sp007_fail_many_broad():
    from entralint.checks.service_principals.sp_broad_delegated_perms import (
        sp_broad_delegated_perms,
    )

    SpBroadDelegatedPerms = sp_broad_delegated_perms.SpBroadDelegatedPerms

    grants = [
        {
            "clientId": "sp1",
            "consentType": "AllPrincipals",
            "scope": (
                "Mail.ReadWrite Mail.Send Files.ReadWrite.All "
                "Sites.ReadWrite.All"
            ),
        }
    ]
    ctx = TenantContext(oauth2_permission_grants=grants)
    findings = SpBroadDelegatedPerms().execute(ctx)
    assert findings[0].status == Status.FAIL


def test_sp007_pass_empty():
    from entralint.checks.service_principals.sp_broad_delegated_perms import (
        sp_broad_delegated_perms,
    )

    SpBroadDelegatedPerms = sp_broad_delegated_perms.SpBroadDelegatedPerms

    ctx = TenantContext(oauth2_permission_grants=[])
    assert SpBroadDelegatedPerms().execute(ctx)[0].status == Status.PASS


# ── user_005: Guest CA excluded ──────────────────────────────


def test_user005_pass_no_exclusions():
    from entralint.checks.users.user_guest_ca_excluded.user_guest_ca_excluded import (
        UserGuestCaExcluded,
    )

    ctx = TenantContext(conditional_access_policies=[_ca()])
    assert UserGuestCaExcluded().execute(ctx)[0].status == Status.PASS


def test_user005_fail_guest_excluded():
    from entralint.checks.users.user_guest_ca_excluded.user_guest_ca_excluded import (
        UserGuestCaExcluded,
    )

    u = ConditionalAccessConditionUsers(
        exclude_users=["GuestsOrExternalUsers"],
    )
    ctx = TenantContext(conditional_access_policies=[_ca(users=u)])
    findings = UserGuestCaExcluded().execute(ctx)
    assert findings[0].status == Status.FAIL


def test_user005_ignores_disabled():
    from entralint.checks.users.user_guest_ca_excluded.user_guest_ca_excluded import (
        UserGuestCaExcluded,
    )

    u = ConditionalAccessConditionUsers(
        exclude_users=["GuestsOrExternalUsers"],
    )
    p = _ca(state="disabled", users=u)
    ctx = TenantContext(conditional_access_policies=[p])
    assert UserGuestCaExcluded().execute(ctx)[0].status == Status.PASS


# ── user_006: Bulk guests ───────────────────────────────────


def test_user006_pass_few_guests():
    from entralint.checks.users.user_bulk_guests.user_bulk_guests import (
        UserBulkGuests,
    )

    users = [
        User(id=f"g{i}", user_type="Guest") for i in range(10)
    ]
    ctx = TenantContext(users=users)
    assert UserBulkGuests().execute(ctx)[0].status == Status.PASS


def test_user006_fail_many_guests():
    from entralint.checks.users.user_bulk_guests.user_bulk_guests import (
        UserBulkGuests,
    )

    users = [
        User(id=f"g{i}", user_type="Guest") for i in range(51)
    ]
    ctx = TenantContext(users=users)
    findings = UserBulkGuests().execute(ctx)
    assert findings[0].status == Status.FAIL
    assert "51" in findings[0].title


def test_user006_pass_no_guests():
    from entralint.checks.users.user_bulk_guests.user_bulk_guests import (
        UserBulkGuests,
    )

    users = [User(id="u1", user_type="Member")]
    ctx = TenantContext(users=users)
    assert UserBulkGuests().execute(ctx)[0].status == Status.PASS


# ── role_006: High-priv role counts ─────────────────────────


def test_role006_pass_few_assignments():
    from entralint.checks.privileged_roles.role_high_priv_count.role_high_priv_count import (
        RoleHighPrivCount,
    )

    app_admin = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"
    ras = [
        DirectoryRoleAssignment(
            id=f"ra{i}",
            principal_id=f"u{i}",
            role_definition_id=app_admin,
        )
        for i in range(3)
    ]
    ctx = TenantContext(role_assignments=ras)
    assert RoleHighPrivCount().execute(ctx)[0].status == Status.PASS


def test_role006_fail_excessive():
    from entralint.checks.privileged_roles.role_high_priv_count.role_high_priv_count import (
        RoleHighPrivCount,
    )

    sec_admin = "194ae4cb-b126-40b2-bd5b-6091b380977d"
    ras = [
        DirectoryRoleAssignment(
            id=f"ra{i}",
            principal_id=f"u{i}",
            role_definition_id=sec_admin,
        )
        for i in range(6)
    ]
    ctx = TenantContext(role_assignments=ras)
    findings = RoleHighPrivCount().execute(ctx)
    assert findings[0].status == Status.FAIL
    assert "Security Administrator" in findings[0].title


def test_role006_ignores_ga():
    from entralint.checks.privileged_roles.role_high_priv_count.role_high_priv_count import (
        RoleHighPrivCount,
    )

    ga_role = "62e90394-69f5-4237-9190-012177145e10"
    ras = [
        DirectoryRoleAssignment(
            id=f"ra{i}",
            principal_id=f"u{i}",
            role_definition_id=ga_role,
        )
        for i in range(10)
    ]
    ctx = TenantContext(role_assignments=ras)
    # GA is excluded — handled by role_001
    assert RoleHighPrivCount().execute(ctx)[0].status == Status.PASS
