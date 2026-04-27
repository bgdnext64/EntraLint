<#
.SYNOPSIS
    Seed (or tear down) intentional misconfigurations in an Entra ID tenant
    so EntraLint has findings to demonstrate.

.DESCRIPTION
    "Dorks" a tenant by creating apps, users, service principals, agent
    identities, and tweaking authorizationPolicy so EntraLint checks flip
    from PASS to FAIL.

    All resources are tagged with a known display-name prefix (default
    "EntraLint-Demo-") so teardown is precise. Original policy values are
    snapshotted into a state file before mutation and restored on teardown.

    DO NOT run against a production tenant. Designed for dedicated demo /
    test tenants.

.PARAMETER Action
    Setup    (default) Create misconfigurations.
    Teardown Restore policies and delete every object recorded in the state
             file.

.PARAMETER Tier
    1   Safe, easily reversible misconfigurations (apps, guests, org policy).
    2   Privileged role assignments and admin consents. Requires confirmation.
    All Tier 1 + Tier 2.

.PARAMETER Agent
    Also seed agent-identity blueprint / agent objects (separate from tiers).

.PARAMETER TenantId
    Target tenant. If omitted, uses the tenant from the current `az` session.

.PARAMETER Prefix
    Display-name prefix used to tag every created object. Default
    "EntraLint-Demo-". Teardown deletes objects recorded in the state file
    only, so changing this between Setup and Teardown is safe.

.PARAMETER StateFile
    Path to the JSON state file. Default scripts/.demo-state.json.

.PARAMETER Force
    Skip confirmation prompts (Tier 2, Teardown).

.PARAMETER WhatIf
    Standard PowerShell dry-run. Prints intended actions without calling
    Graph.

.EXAMPLE
    pwsh ./scripts/seed_demo_findings.ps1 -Tier 1 -WhatIf

.EXAMPLE
    pwsh ./scripts/seed_demo_findings.ps1 -Tier 1 -Agent

.EXAMPLE
    pwsh ./scripts/seed_demo_findings.ps1 -Action Teardown

.NOTES
    Requires `az login` with at least:
      - Application Administrator
      - User Administrator
      - Privileged Role Administrator (for Tier 2)
      - Cloud Application Administrator (for admin consent in Tier 2)
    Or simply Global Administrator in a demo tenant.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [ValidateSet('Setup', 'Teardown')]
    [string]$Action = 'Setup',

    [ValidateSet('1', '2', 'All', 'None')]
    [string]$Tier = '1',

    [switch]$Agent,

    [string]$TenantId,

    [string]$Prefix = 'EntraLint-Demo-',

    [string]$StateFile = (Join-Path $PSScriptRoot '.demo-state.json'),

    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$script:GraphBase = 'https://graph.microsoft.com/v1.0'
$script:GraphBeta = 'https://graph.microsoft.com/beta'
$script:State = $null
$script:MgAgentConnected = $false

# ---------------------------------------------------------------------------
# Graph helpers (delegated through `az rest`)
# ---------------------------------------------------------------------------

function Invoke-Graph {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateSet('GET', 'POST', 'PATCH', 'PUT', 'DELETE')] [string]$Method,
        [Parameter(Mandatory)] [string]$Uri,
        [object]$Body,
        [switch]$IgnoreError
    )
    $args = @('rest', '--method', $Method.ToLower(), '--uri', $Uri,
        '--headers', 'Content-Type=application/json')
    if ($null -ne $Body) {
        $json = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 10 -Compress }
        $tmp = New-TemporaryFile
        Set-Content -Path $tmp -Value $json -Encoding utf8 -NoNewline
        $args += @('--body', "@$tmp")
    }
    $raw = & az @args 2>&1
    if ($null -ne $tmp) { Remove-Item -Path $tmp -ErrorAction SilentlyContinue }
    if ($LASTEXITCODE -ne 0) {
        if ($IgnoreError) { return $null }
        throw "Graph $Method $Uri failed: $raw"
    }
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    try { return $raw | ConvertFrom-Json } catch { return $raw }
}

function Get-CurrentUser {
    Invoke-Graph -Method GET -Uri "$script:GraphBase/me"
}

function Connect-MgAgentSession {
    <#
    .SYNOPSIS
    Establishes a Microsoft Graph PowerShell connection with ONLY the
    Agent ID scopes. Required because Microsoft's Agent APIs reject any
    token that includes Directory.AccessAsUser.All (which az CLI tokens
    always contain). Disconnects any prior session first to drop the
    broader scope set.
    #>
    if ($script:MgAgentConnected) { return }
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw "Microsoft.Graph.Authentication module not installed. Run: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser"
    }
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
    Connect-MgGraph -TenantId $script:TenantId -Scopes @(
        'AgentIdentity.ReadWrite.All',
        'Application.ReadWrite.All'
    ) -NoWelcome -ErrorAction Stop
    $script:MgAgentConnected = $true
}

function Invoke-MgAgent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateSet('GET', 'POST', 'PATCH', 'PUT', 'DELETE')] [string]$Method,
        [Parameter(Mandatory)] [string]$Uri,
        [object]$Body,
        [switch]$IgnoreError
    )
    Connect-MgAgentSession
    try {
        if ($null -ne $Body) {
            $json = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 10 -Compress }
            return Invoke-MgGraphRequest -Method $Method -Uri $Uri -Body $json -ContentType 'application/json' -ErrorAction Stop
        }
        return Invoke-MgGraphRequest -Method $Method -Uri $Uri -ErrorAction Stop
    }
    catch {
        if ($IgnoreError) {
            Write-Warning "Mg $Method $Uri failed: $_"
            return $null
        }
        throw "Mg $Method $Uri failed: $_"
    }
}

# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------

function Initialize-State {
    if (Test-Path $StateFile) {
        $script:State = Get-Content $StateFile -Raw | ConvertFrom-Json
    }
    else {
        $script:State = [pscustomobject]@{
            tenantId    = $TenantId
            createdAt   = (Get-Date).ToString('o')
            prefix      = $Prefix
            objects     = [pscustomobject]@{
                users             = @()
                applications      = @()
                servicePrincipals = @()
                agentBlueprints   = @()
                agentBlueprintPrincipals = @()
                agentIdentities   = @()
                roleAssignments   = @()
                groups            = @()
            }
            policies    = [pscustomobject]@{}
        }
    }
    # Migrate older state files that may be missing newer object kinds.
    foreach ($kind in @('users', 'applications', 'servicePrincipals', 'agentBlueprints',
                        'agentBlueprintPrincipals', 'agentIdentities', 'roleAssignments', 'groups')) {
        if (-not $script:State.objects.PSObject.Properties[$kind]) {
            $script:State.objects | Add-Member -NotePropertyName $kind -NotePropertyValue @() -Force
        }
    }
}

function Save-State {
    if ($PSCmdlet.ShouldProcess($StateFile, 'Save state')) {
        $script:State | ConvertTo-Json -Depth 20 | Set-Content -Path $StateFile -Encoding utf8
    }
}

function Add-StateObject {
    param(
        [Parameter(Mandatory)][ValidateSet('users', 'applications', 'servicePrincipals',
            'agentBlueprints', 'agentBlueprintPrincipals', 'agentIdentities', 'roleAssignments', 'groups')]
        [string]$Kind,
        [Parameter(Mandatory)][object]$Obj
    )
    $list = @($script:State.objects.$Kind)
    if (-not ($list | Where-Object { $_.id -eq $Obj.id })) {
        $list += $Obj
        $script:State.objects.$Kind = $list
    }
}

function Save-PolicySnapshot {
    param([string]$Key, [object]$Snapshot)
    if (-not ($script:State.policies.PSObject.Properties.Name -contains $Key)) {
        $script:State.policies | Add-Member -NotePropertyName $Key -NotePropertyValue $Snapshot
    }
}

# ---------------------------------------------------------------------------
# Naming helpers
# ---------------------------------------------------------------------------

function New-DemoName {
    param([string]$Slug)
    $stamp = (Get-Date).ToString('yyMMddHHmm')
    return "$Prefix$Slug-$stamp"
}

function Get-DefaultDomain {
    $org = Invoke-Graph -Method GET -Uri "$script:GraphBase/organization"
    $verified = $org.value[0].verifiedDomains | Where-Object { $_.isInitial -eq $true } | Select-Object -First 1
    if (-not $verified) { $verified = $org.value[0].verifiedDomains | Select-Object -First 1 }
    return $verified.name
}

# ---------------------------------------------------------------------------
# Tier 1 seeders
# ---------------------------------------------------------------------------

# Microsoft Graph well-known IDs
$ROLE_ROLEMANAGEMENT_RW    = '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8'  # RoleManagement.ReadWrite.Directory
$ROLE_APPLICATION_RW       = '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9'  # Application.ReadWrite.All
$ROLE_DIRECTORY_RW         = '19dbc75e-c2e2-444c-a770-ec69d8559fc7'  # Directory.ReadWrite.All
$SCOPE_USER_READ           = 'e1fe6dd8-ba31-4d61-89e7-88639da4683d'  # User.Read (delegated)
$SCOPE_FILES_RW            = '5c28f0bf-8a70-41f1-8ab2-9032436ddb65'  # Files.ReadWrite.All (delegated)
$SCOPE_MAIL_RW             = '024d486e-b451-40bb-833d-3e66d98c5c73'  # Mail.ReadWrite (delegated)
$SCOPE_GROUP_RW            = '4e46008b-f24c-477d-8fff-7bb4ec7aafe0'  # Group.ReadWrite.All (delegated)
$SCOPE_DIRECTORY_AW        = '0e263e50-5827-48a4-b97c-d940288653c7'  # Directory.AccessAsUser.All
$GRAPH_RESOURCE_APP_ID     = '00000003-0000-0000-c000-000000000000'

$ROLE_DEF_DIRECTORY_READER       = '88d8e3e3-8f55-4a1e-953a-9b9898b8876b'
$ROLE_DEF_APPLICATION_ADMIN      = '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'
$ROLE_DEF_CLOUD_APPLICATION_ADMIN = '158c047a-c907-4556-b7ef-446551a6b5f7'

function Seed-AppHighPrivPerms {
    # entraid_app_005 (HIGH)
    $name = New-DemoName -Slug 'AppHighPriv'
    if ($PSCmdlet.ShouldProcess($name, 'Create app with high-privilege permissions')) {
        $body = @{
            displayName            = $name
            signInAudience         = 'AzureADMyOrg'
            requiredResourceAccess = @(@{
                    resourceAppId  = $GRAPH_RESOURCE_APP_ID
                    resourceAccess = @(
                        @{ id = $ROLE_ROLEMANAGEMENT_RW; type = 'Role' },
                        @{ id = $ROLE_APPLICATION_RW;    type = 'Role' },
                        @{ id = $ROLE_DIRECTORY_RW;      type = 'Role' }
                    )
                })
        }
        $app = Invoke-Graph -Method POST -Uri "$script:GraphBase/applications" -Body $body
        Add-StateObject -Kind applications -Obj ([pscustomobject]@{ id = $app.id; appId = $app.appId; displayName = $name })
        Write-Host "  [app_005] Created '$name' (id=$($app.id))" -ForegroundColor Green
        return $app
    }
}

function Seed-AppExcessiveDelegated {
    # entraid_app_009 (MEDIUM)
    $name = New-DemoName -Slug 'AppDelegatedScopes'
    if ($PSCmdlet.ShouldProcess($name, 'Create app requesting excessive delegated scopes')) {
        $body = @{
            displayName            = $name
            signInAudience         = 'AzureADMyOrg'
            requiredResourceAccess = @(@{
                    resourceAppId  = $GRAPH_RESOURCE_APP_ID
                    resourceAccess = @(
                        @{ id = $SCOPE_USER_READ;    type = 'Scope' },
                        @{ id = $SCOPE_FILES_RW;     type = 'Scope' },
                        @{ id = $SCOPE_MAIL_RW;      type = 'Scope' },
                        @{ id = $SCOPE_GROUP_RW;     type = 'Scope' },
                        @{ id = $SCOPE_DIRECTORY_AW; type = 'Scope' }
                    )
                })
        }
        $app = Invoke-Graph -Method POST -Uri "$script:GraphBase/applications" -Body $body
        Add-StateObject -Kind applications -Obj ([pscustomobject]@{ id = $app.id; appId = $app.appId; displayName = $name })
        Write-Host "  [app_009] Created '$name'" -ForegroundColor Green
        return $app
    }
}

function Seed-NonAdminOwnerOnPrivApp {
    # entraid_app_007 (CRITICAL) -- needs a non-admin user owner on a high-priv app.
    param([Parameter(Mandatory)]$App)
    $domain = Get-DefaultDomain
    $userName = New-DemoName -Slug 'AppOwner'
    $upn = "$userName@$domain"
    if ($PSCmdlet.ShouldProcess($upn, 'Create non-admin user and assign as app owner')) {
        $nick = ($userName -replace '[^A-Za-z0-9]', '')
        $userBody = @{
            accountEnabled    = $true
            displayName       = $userName
            mailNickname      = $nick.Substring(0, [Math]::Min(40, $nick.Length))
            userPrincipalName = $upn
            passwordProfile   = @{
                forceChangePasswordNextSignIn = $true
                password                      = ('A!' + [Guid]::NewGuid().ToString('N').Substring(0, 14))
            }
        }
        $user = Invoke-Graph -Method POST -Uri "$script:GraphBase/users" -Body $userBody
        Add-StateObject -Kind users -Obj ([pscustomobject]@{ id = $user.id; upn = $upn })

        $ownerBody = @{ '@odata.id' = "$script:GraphBase/directoryObjects/$($user.id)" }
        Invoke-Graph -Method POST -Uri "$script:GraphBase/applications/$($App.id)/owners/`$ref" -Body $ownerBody | Out-Null
        Write-Host "  [app_007] Assigned non-admin '$upn' as owner of '$($App.displayName)'" -ForegroundColor Green
    }
}

function Seed-DisabledSPWithCreds {
    # entraid_sp_001 (HIGH) and entraid_sp_009 (LOW): SP with active creds, then disabled.
    $name = New-DemoName -Slug 'DisabledSP'
    if ($PSCmdlet.ShouldProcess($name, 'Create app+SP with creds, then disable')) {
        $app = Invoke-Graph -Method POST -Uri "$script:GraphBase/applications" -Body @{ displayName = $name }
        Add-StateObject -Kind applications -Obj ([pscustomobject]@{ id = $app.id; appId = $app.appId; displayName = $name })

        $sp = Invoke-Graph -Method POST -Uri "$script:GraphBase/servicePrincipals" -Body @{ appId = $app.appId }
        Add-StateObject -Kind servicePrincipals -Obj ([pscustomobject]@{ id = $sp.id; appId = $app.appId })

        # Add password credential
        Invoke-Graph -Method POST -Uri "$script:GraphBase/applications/$($app.id)/addPassword" `
            -Body @{ passwordCredential = @{ displayName = 'demo-secret' } } | Out-Null

        # Add a self-signed-ish key credential (entraid_sp_009 needs both password+key on the SP)
        $cert = New-DemoSelfSignedCert -Subject "CN=$name"
        if ($cert) {
            $keyBody = @{
                keyCredentials = @(@{
                        type        = 'AsymmetricX509Cert'
                        usage       = 'Verify'
                        displayName = 'demo-cert'
                        key         = $cert
                    })
                passwordCredentials = @()  # left untouched by patch on application; the addPassword already added one.
            }
            # Patch the SP directly so both creds live on the SP for sp_009.
            Invoke-Graph -Method PATCH -Uri "$script:GraphBase/servicePrincipals/$($sp.id)" `
                -Body @{ keyCredentials = $keyBody.keyCredentials } | Out-Null
        }

        # Disable the SP -> sp_001 fires
        Invoke-Graph -Method PATCH -Uri "$script:GraphBase/servicePrincipals/$($sp.id)" `
            -Body @{ accountEnabled = $false } | Out-Null
        Write-Host "  [sp_001/sp_009] Disabled SP '$name' with active credentials" -ForegroundColor Green
    }
}

function New-DemoSelfSignedCert {
    param([string]$Subject)
    try {
        $cert = New-SelfSignedCertificate -Subject $Subject -CertStoreLocation 'Cert:\CurrentUser\My' `
            -KeyExportPolicy NonExportable -NotAfter (Get-Date).AddDays(30) -ErrorAction Stop
        $b64 = [Convert]::ToBase64String($cert.RawData)
        # Best-effort cleanup of the local cert store
        Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -ErrorAction SilentlyContinue
        return $b64
    }
    catch {
        Write-Host "  [warn] Could not generate self-signed cert: $_" -ForegroundColor Yellow
        return $null
    }
}

function Seed-DisabledMember {
    # entraid_user_002 (LOW): disabled member account
    $domain = Get-DefaultDomain
    $name = New-DemoName -Slug 'DisabledUser'
    $upn = "$name@$domain"
    if ($PSCmdlet.ShouldProcess($upn, 'Create disabled member user')) {
        $nick = ($name -replace '[^A-Za-z0-9]', '')
        $body = @{
            accountEnabled    = $false
            displayName       = $name
            mailNickname      = $nick.Substring(0, [Math]::Min(40, $nick.Length))
            userPrincipalName = $upn
            passwordProfile   = @{
                forceChangePasswordNextSignIn = $true
                password                      = ('A!' + [Guid]::NewGuid().ToString('N').Substring(0, 14))
            }
        }
        $user = Invoke-Graph -Method POST -Uri "$script:GraphBase/users" -Body $body
        Add-StateObject -Kind users -Obj ([pscustomobject]@{ id = $user.id; upn = $upn })
        Write-Host "  [user_002] Created disabled member '$upn'" -ForegroundColor Green
        return $user
    }
}

function Seed-GuestInvites {
    # entraid_user_001 / user_006 / user_008: invite a few guests
    for ($i = 1; $i -le 3; $i++) {
        $invitedEmail = "demo-guest-$i-$([Guid]::NewGuid().ToString('N').Substring(0,6))@example.com"
        $name = "$Prefix" + "Guest-$i"
        if ($PSCmdlet.ShouldProcess($invitedEmail, "Invite guest #$i")) {
            $body = @{
                invitedUserEmailAddress = $invitedEmail
                invitedUserDisplayName  = $name
                inviteRedirectUrl       = 'https://example.com'
                sendInvitationMessage   = $false
            }
            $invite = Invoke-Graph -Method POST -Uri "$script:GraphBase/invitations" -Body $body
            if ($invite -and $invite.invitedUser) {
                Add-StateObject -Kind users -Obj ([pscustomobject]@{
                        id  = $invite.invitedUser.id
                        upn = $invitedEmail
                    })
                Write-Host "  [user_001/006/008] Invited guest '$invitedEmail'" -ForegroundColor Green
            }
        }
    }
}

function Seed-OrgPolicy {
    # entraid_org_002 (HIGH), entraid_org_003 (MEDIUM), entraid_org_009 (MEDIUM)
    $current = Invoke-Graph -Method GET -Uri "$script:GraphBase/policies/authorizationPolicy"
    Save-PolicySnapshot -Key 'authorizationPolicy' -Snapshot $current

    $patch = @{
        allowInvitesFrom            = 'everyone'   # org_003
        defaultUserRolePermissions  = @{
            allowedToCreateApps = $true            # org_009
            permissionGrantPoliciesAssigned = @(
                'ManagePermissionGrantsForSelf.microsoft-user-default-legacy'  # org_002 broad consent
            )
        }
    }
    if ($PSCmdlet.ShouldProcess('authorizationPolicy', 'Patch org_002/003/009')) {
        Invoke-Graph -Method PATCH -Uri "$script:GraphBase/policies/authorizationPolicy" -Body $patch | Out-Null
        Write-Host "  [org_002/org_003/org_009] Patched authorizationPolicy" -ForegroundColor Green
    }
}

# ---------------------------------------------------------------------------
# Tier 2 seeders (privileged, opt-in)
# ---------------------------------------------------------------------------

function Add-RoleAssignment {
    param([string]$RoleDefId, [string]$PrincipalId, [string]$CheckId)
    $body = @{
        '@odata.type'    = '#microsoft.graph.unifiedRoleAssignment'
        roleDefinitionId = $RoleDefId
        principalId      = $PrincipalId
        directoryScopeId = '/'
    }
    $assign = Invoke-Graph -Method POST -Uri "$script:GraphBase/roleManagement/directory/roleAssignments" -Body $body -IgnoreError
    if ($assign -and $assign.id) {
        Add-StateObject -Kind roleAssignments -Obj ([pscustomobject]@{ id = $assign.id; principalId = $PrincipalId })
        Write-Host "  [$CheckId] Assigned role $RoleDefId to principal $PrincipalId" -ForegroundColor Green
    }
}

function Seed-Tier2 {
    # role_004: guest with privileged role
    $domain = Get-DefaultDomain
    $email = "demo-guest-priv-$([Guid]::NewGuid().ToString('N').Substring(0,6))@example.com"
    if ($PSCmdlet.ShouldProcess($email, 'Invite guest and assign Directory Reader role (role_004)')) {
        $invite = Invoke-Graph -Method POST -Uri "$script:GraphBase/invitations" -Body @{
            invitedUserEmailAddress = $email
            invitedUserDisplayName  = "${Prefix}PrivGuest"
            inviteRedirectUrl       = 'https://example.com'
            sendInvitationMessage   = $false
        }
        if ($invite -and $invite.invitedUser) {
            Add-StateObject -Kind users -Obj ([pscustomobject]@{ id = $invite.invitedUser.id; upn = $email })
            Add-RoleAssignment -RoleDefId $ROLE_DEF_DIRECTORY_READER -PrincipalId $invite.invitedUser.id -CheckId 'role_004'
        }
    }

    # role_005: SP with privileged directory role
    $spName = New-DemoName -Slug 'PrivSP'
    if ($PSCmdlet.ShouldProcess($spName, 'Create SP and assign Directory Reader role (role_005)')) {
        $app = Invoke-Graph -Method POST -Uri "$script:GraphBase/applications" -Body @{ displayName = $spName }
        Add-StateObject -Kind applications -Obj ([pscustomobject]@{ id = $app.id; appId = $app.appId; displayName = $spName })
        $sp = Invoke-Graph -Method POST -Uri "$script:GraphBase/servicePrincipals" -Body @{ appId = $app.appId }
        Add-StateObject -Kind servicePrincipals -Obj ([pscustomobject]@{ id = $sp.id; appId = $app.appId })
        Add-RoleAssignment -RoleDefId $ROLE_DEF_DIRECTORY_READER -PrincipalId $sp.id -CheckId 'role_005'
    }

    # role_009 / role_010: bulk app admin assignments
    $domain = Get-DefaultDomain
    foreach ($pair in @(
            @{ slug = 'AppAdmin'; role = $ROLE_DEF_APPLICATION_ADMIN; check = 'role_009' },
            @{ slug = 'CloudAppAdmin'; role = $ROLE_DEF_CLOUD_APPLICATION_ADMIN; check = 'role_010' }
        )) {
        $userName = New-DemoName -Slug $pair.slug
        $upn = "$userName@$domain"
        if ($PSCmdlet.ShouldProcess($upn, "Create user and assign $($pair.slug) role ($($pair.check))")) {
            $nick = ($userName -replace '[^A-Za-z0-9]', '')
            $user = Invoke-Graph -Method POST -Uri "$script:GraphBase/users" -Body @{
                accountEnabled    = $true
                displayName       = $userName
                mailNickname      = $nick.Substring(0, [Math]::Min(40, $nick.Length))
                userPrincipalName = $upn
                passwordProfile   = @{
                    forceChangePasswordNextSignIn = $true
                    password                      = ('A!' + [Guid]::NewGuid().ToString('N').Substring(0, 14))
                }
            }
            Add-StateObject -Kind users -Obj ([pscustomobject]@{ id = $user.id; upn = $upn })
            Add-RoleAssignment -RoleDefId $pair.role -PrincipalId $user.id -CheckId $pair.check
        }
    }
}

# ---------------------------------------------------------------------------
# Agent identity seeders (separate from tiers)
# ---------------------------------------------------------------------------

function Seed-AgentIdentities {
    # NOTE: Agent APIs reject tokens containing Directory.AccessAsUser.All
    # (which az CLI tokens always include). We use Microsoft.Graph PowerShell
    # with a narrow scope set instead. See Connect-MgAgentSession.
    try { Connect-MgAgentSession } catch {
        Write-Warning "Cannot connect to Mg with agent scopes: $_"
        return
    }

    $me = Get-CurrentUser
    $sponsorUri = "$script:GraphBase/users/$($me.id)"

    $blueprints = @(
        @{ slug = 'AgentBP-Good';     body = @{ displayName = (New-DemoName 'AgentBP-Good');     description = 'Well-configured agent blueprint';   'sponsors@odata.bind' = @($sponsorUri) } },
        @{ slug = 'AgentBP-NoDesc';   body = @{ displayName = (New-DemoName 'AgentBP-NoDesc');                                                       'sponsors@odata.bind' = @($sponsorUri) } },
        @{ slug = 'AgentBP-Overpriv'; body = @{ displayName = (New-DemoName 'AgentBP-Overpriv'); description = 'Overprivileged agent blueprint';     'sponsors@odata.bind' = @($sponsorUri) } },
        @{ slug = 'AgentBP-Secret';   body = @{ displayName = (New-DemoName 'AgentBP-Secret');   description = 'Uses client secrets';                'sponsors@odata.bind' = @($sponsorUri) } }
    )

    $created = @{}
    foreach ($bp in $blueprints) {
        if ($PSCmdlet.ShouldProcess($bp.body.displayName, 'Create agent identity blueprint')) {
            $resp = Invoke-MgAgent -Method POST -Uri "$script:GraphBase/applications/microsoft.graph.agentIdentityBlueprint" -Body $bp.body -IgnoreError
            if ($resp -and $resp.id) {
                Add-StateObject -Kind agentBlueprints -Obj ([pscustomobject]@{ id = $resp.id; appId = $resp.appId; displayName = $bp.body.displayName })
                $created[$bp.slug] = $resp
                Write-Host "  [agent] Created blueprint '$($bp.body.displayName)'" -ForegroundColor Green
            }
        }
    }

    if ($created['AgentBP-Secret']) {
        if ($PSCmdlet.ShouldProcess($created['AgentBP-Secret'].id, 'Add password credential to secret-based blueprint')) {
            Invoke-MgAgent -Method POST -Uri "$script:GraphBase/applications/$($created['AgentBP-Secret'].id)/addPassword" `
                -Body @{ passwordCredential = @{ displayName = 'agent-test-secret' } } -IgnoreError | Out-Null
        }
    }

    # Each blueprint application needs a corresponding servicePrincipal
    # ("blueprint principal") before any agentIdentity can reference it.
    foreach ($slug in @($created.Keys)) {
        $bp = $created[$slug]
        if (-not $bp.appId) { continue }
        if ($PSCmdlet.ShouldProcess($bp.appId, "Create blueprint principal for $slug")) {
            $sp = Invoke-MgAgent -Method POST -Uri "$script:GraphBase/servicePrincipals" `
                -Body @{ appId = $bp.appId } -IgnoreError
            if ($sp -and $sp.id) {
                Add-StateObject -Kind agentBlueprintPrincipals -Obj ([pscustomobject]@{ id = $sp.id; appId = $bp.appId; blueprintSlug = $slug })
                Write-Host "  [agent] Created blueprint principal for '$slug' (sp=$($sp.id))" -ForegroundColor DarkGreen
            }
        }
    }

    foreach ($pair in @(
            @{ slug = 'Agent-Good';     bp = 'AgentBP-Good' },
            @{ slug = 'Agent-NoDesc';   bp = 'AgentBP-NoDesc' },
            @{ slug = 'Agent-Overpriv'; bp = 'AgentBP-Overpriv' }
        )) {
        $bp = $created[$pair.bp]
        if (-not $bp) { continue }
        $name = New-DemoName -Slug $pair.slug
        if ($PSCmdlet.ShouldProcess($name, 'Create agent identity')) {
            $resp = Invoke-MgAgent -Method POST -Uri "$script:GraphBase/servicePrincipals/microsoft.graph.agentIdentity" `
                -Body @{ displayName = $name; agentIdentityBlueprintId = $bp.id; 'sponsors@odata.bind' = @($sponsorUri) } -IgnoreError
            if ($resp -and $resp.id) {
                Add-StateObject -Kind agentIdentities -Obj ([pscustomobject]@{ id = $resp.id; displayName = $name })
                Write-Host "  [agent] Created agent '$name'" -ForegroundColor Green
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------

function Remove-StateObjects {
    $deletions = @(
        @{ kind = 'roleAssignments';          uriTpl = "$script:GraphBase/roleManagement/directory/roleAssignments/{0}"; useMg = $false },
        @{ kind = 'agentIdentities';          uriTpl = "$script:GraphBase/servicePrincipals/{0}";                        useMg = $true  },
        # Blueprint principals (servicePrincipals for the blueprint app) cannot
        # be deleted directly (Authorization_RequestDenied). They cascade away
        # when the parent blueprint application is deleted, so we just clear
        # the state entry without an HTTP call.
        @{ kind = 'agentBlueprintPrincipals'; uriTpl = $null;                                                              useMg = $false; skipDelete = $true },
        @{ kind = 'agentBlueprints';          uriTpl = "$script:GraphBase/applications/{0}";                             useMg = $true  },
        @{ kind = 'servicePrincipals';        uriTpl = "$script:GraphBase/servicePrincipals/{0}";                        useMg = $false },
        @{ kind = 'applications';             uriTpl = "$script:GraphBase/applications/{0}";                             useMg = $false },
        @{ kind = 'users';                    uriTpl = "$script:GraphBase/users/{0}";                                    useMg = $false },
        @{ kind = 'groups';                   uriTpl = "$script:GraphBase/groups/{0}";                                   useMg = $false }
    )
    foreach ($d in $deletions) {
        $items = @($script:State.objects.($d.kind))
        if ($d.skipDelete) {
            if ($items.Count -gt 0) {
                Write-Host "  Skipping direct delete of $($d.kind) ($($items.Count) item(s)) - cascades with parent blueprint" -ForegroundColor DarkGray
            }
            $script:State.objects.($d.kind) = @()
            continue
        }
        if ($d.useMg -and $items.Count -gt 0) {
            try { Connect-MgAgentSession } catch { Write-Warning "Skipping $($d.kind) deletion (Mg connect failed): $_"; continue }
        }
        foreach ($obj in $items) {
            if (-not $obj -or -not $obj.id) { continue }
            $uri = [string]::Format($d.uriTpl, $obj.id)
            if ($PSCmdlet.ShouldProcess($uri, "Delete $($d.kind)")) {
                if ($d.useMg) {
                    Invoke-MgAgent -Method DELETE -Uri $uri -IgnoreError | Out-Null
                } else {
                    Invoke-Graph -Method DELETE -Uri $uri -IgnoreError | Out-Null
                }
                Write-Host "  Removed $($d.kind): $($obj.id)" -ForegroundColor DarkGray
            }
        }
        $script:State.objects.($d.kind) = @()
    }
}

function Restore-Policies {
    foreach ($prop in $script:State.policies.PSObject.Properties) {
        if ($prop.Name -eq 'authorizationPolicy') {
            $orig = $prop.Value
            $patch = @{
                allowInvitesFrom            = $orig.allowInvitesFrom
                defaultUserRolePermissions  = $orig.defaultUserRolePermissions
            }
            if ($PSCmdlet.ShouldProcess('authorizationPolicy', 'Restore original')) {
                Invoke-Graph -Method PATCH -Uri "$script:GraphBase/policies/authorizationPolicy" -Body $patch | Out-Null
                Write-Host "  Restored authorizationPolicy" -ForegroundColor Green
            }
        }
    }
    $script:State.policies = [pscustomobject]@{}
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

function Confirm-Tier2 {
    if ($Force) { return $true }
    Write-Host ""
    Write-Host "Tier 2 will create privileged role assignments (role_004, role_005, role_009, role_010)." -ForegroundColor Yellow
    Write-Host "These are reversible but visible in audit logs."
    $r = Read-Host "Type 'YES' to continue"
    return ($r -eq 'YES')
}

function Confirm-Teardown {
    if ($Force) { return $true }
    if (-not (Test-Path $StateFile)) { Write-Host "No state file at $StateFile, nothing to tear down." -ForegroundColor Yellow; return $false }
    Write-Host ""
    Write-Host "Teardown will delete every recorded object and restore policies." -ForegroundColor Yellow
    $r = Read-Host "Type 'YES' to continue"
    return ($r -eq 'YES')
}

# Verify az session
try {
    $azCtx = & az account show 2>$null | ConvertFrom-Json
    if (-not $azCtx) { throw 'az account show returned nothing' }
    if ($TenantId -and $azCtx.tenantId -ne $TenantId) {
        throw "az session is on tenant $($azCtx.tenantId) but -TenantId is $TenantId. Run 'az login --tenant $TenantId' first."
    }
    if (-not $TenantId) { $TenantId = $azCtx.tenantId }
    $script:TenantId = $TenantId
    Write-Host "Tenant: $TenantId  ($($azCtx.user.name))" -ForegroundColor Cyan
}
catch {
    Write-Error "az CLI not authenticated. Run 'az login' first.`n$_"
    exit 1
}

Initialize-State

if ($Action -eq 'Setup') {
    if ($Tier -in @('1', 'All', 'None') -and $Tier -ne 'None') {
        Write-Host "`n=== Seeding Tier 1 ===" -ForegroundColor Cyan
        $tier1Steps = @(
            { Seed-OrgPolicy },
            { $script:hpApp = Seed-AppHighPrivPerms;
                if (-not $script:hpApp -and $WhatIfPreference) {
                    $script:hpApp = [pscustomobject]@{ id = '<whatif>'; displayName = '<whatif-app>' }
                }
            },
            { if ($script:hpApp) { Seed-NonAdminOwnerOnPrivApp -App $script:hpApp } },
            { Seed-AppExcessiveDelegated },
            { Seed-DisabledSPWithCreds },
            { Seed-DisabledMember },
            { Seed-GuestInvites }
        )
        foreach ($step in $tier1Steps) {
            try { & $step } catch { Write-Warning "Step failed (continuing): $_" }
            Save-State
        }
    }
    if ($Tier -in @('2', 'All')) {
        if (Confirm-Tier2) {
            Write-Host "`n=== Seeding Tier 2 ===" -ForegroundColor Cyan
            Seed-Tier2
        }
        else {
            Write-Host "Tier 2 skipped." -ForegroundColor Yellow
        }
    }
    if ($Agent) {
        Write-Host "`n=== Seeding Agent Identities ===" -ForegroundColor Cyan
        try { Seed-AgentIdentities } catch { Write-Warning "Agent seeding failed: $_" }
        Save-State
    }
    Save-State
    Write-Host "`nDone. State file: $StateFile" -ForegroundColor Green
    Write-Host "Run scan with: uv run entralint scan --tenant $TenantId" -ForegroundColor Green
}
elseif ($Action -eq 'Teardown') {
    if (Confirm-Teardown) {
        Write-Host "`n=== Tearing Down ===" -ForegroundColor Cyan
        Restore-Policies
        Remove-StateObjects
        Save-State
        if ($PSCmdlet.ShouldProcess($StateFile, 'Delete state file')) {
            Remove-Item $StateFile -ErrorAction SilentlyContinue
            Write-Host "Removed state file." -ForegroundColor Green
        }
    }
}
