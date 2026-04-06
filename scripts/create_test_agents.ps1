# create_test_agents.ps1
# Creates test agent identities in the tenant to exercise EntraLint checks.
# Requires: az login with AgentIdentityBlueprint.Create + AgentIdentity.CreateAsManager permissions
# (or Agent ID Administrator role)

$ErrorActionPreference = "Continue"
$userId = "b50de0bb-f2db-4a9e-8a26-d7ec5a2f0f55"
$graphBase = "https://graph.microsoft.com/v1.0"
$sponsorUri = "$graphBase/users/$userId"

Write-Host "`n=== Creating Test Agent Identity Blueprints ===" -ForegroundColor Cyan

# --- Blueprint 1: Well-configured blueprint (should pass most checks) ---
Write-Host "`n[1/4] Creating 'Good Agent Blueprint' (well-configured)..." -ForegroundColor Yellow
$bp1Body = @{
    displayName = "EntraLint Test - Good Agent Blueprint"
    description = "A well-configured agent for EntraLint testing"
    "sponsors@odata.bind" = @($sponsorUri)
} | ConvertTo-Json -Depth 5

$bp1 = az rest --method POST `
    --uri "$graphBase/applications/microsoft.graph.agentIdentityBlueprint" `
    --headers "Content-Type=application/json" `
    --body $bp1Body 2>&1
if ($LASTEXITCODE -eq 0) {
    $bp1Obj = $bp1 | ConvertFrom-Json
    Write-Host "  Created blueprint: $($bp1Obj.id) (appId: $($bp1Obj.appId))" -ForegroundColor Green
} else {
    Write-Host "  Failed: $bp1" -ForegroundColor Red
}

# --- Blueprint 2: No description, no sponsors override (should trigger agent_012, agent_006) ---
Write-Host "`n[2/4] Creating 'Bad Agent Blueprint' (missing description)..." -ForegroundColor Yellow
$bp2Body = @{
    displayName = "EntraLint Test - Bad Agent Blueprint"
    "sponsors@odata.bind" = @($sponsorUri)
} | ConvertTo-Json -Depth 5

$bp2 = az rest --method POST `
    --uri "$graphBase/applications/microsoft.graph.agentIdentityBlueprint" `
    --headers "Content-Type=application/json" `
    --body $bp2Body 2>&1
if ($LASTEXITCODE -eq 0) {
    $bp2Obj = $bp2 | ConvertFrom-Json
    Write-Host "  Created blueprint: $($bp2Obj.id) (appId: $($bp2Obj.appId))" -ForegroundColor Green
} else {
    Write-Host "  Failed: $bp2" -ForegroundColor Red
}

# --- Blueprint 3: Minimal blueprint for broad-permission agent ---
Write-Host "`n[3/4] Creating 'Overprivileged Agent Blueprint'..." -ForegroundColor Yellow
$bp3Body = @{
    displayName = "EntraLint Test - Overprivileged Blueprint"
    description = "This blueprint's agents will have too many permissions"
    "sponsors@odata.bind" = @($sponsorUri)
} | ConvertTo-Json -Depth 5

$bp3 = az rest --method POST `
    --uri "$graphBase/applications/microsoft.graph.agentIdentityBlueprint" `
    --headers "Content-Type=application/json" `
    --body $bp3Body 2>&1
if ($LASTEXITCODE -eq 0) {
    $bp3Obj = $bp3 | ConvertFrom-Json
    Write-Host "  Created blueprint: $($bp3Obj.id) (appId: $($bp3Obj.appId))" -ForegroundColor Green
} else {
    Write-Host "  Failed: $bp3" -ForegroundColor Red
}

# --- Blueprint 4: Password credential blueprint (should trigger agent_008) ---
Write-Host "`n[4/4] Creating 'Secret-Based Agent Blueprint'..." -ForegroundColor Yellow
$bp4Body = @{
    displayName = "EntraLint Test - Secret Based Blueprint"
    description = "Uses client secrets instead of federated credentials"
    "sponsors@odata.bind" = @($sponsorUri)
} | ConvertTo-Json -Depth 5

$bp4 = az rest --method POST `
    --uri "$graphBase/applications/microsoft.graph.agentIdentityBlueprint" `
    --headers "Content-Type=application/json" `
    --body $bp4Body 2>&1
if ($LASTEXITCODE -eq 0) {
    $bp4Obj = $bp4 | ConvertFrom-Json
    Write-Host "  Created blueprint: $($bp4Obj.id) (appId: $($bp4Obj.appId))" -ForegroundColor Green

    # Add a password credential to this blueprint to trigger agent_008
    Write-Host "  Adding password credential to blueprint..." -ForegroundColor Yellow
    $pwBody = @{
        passwordCredential = @{
            displayName = "test-secret"
        }
    } | ConvertTo-Json -Depth 5
    $pwResult = az rest --method POST `
        --uri "$graphBase/applications/$($bp4Obj.id)/addPassword" `
        --headers "Content-Type=application/json" `
        --body $pwBody 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  Password credential added" -ForegroundColor Green
    } else {
        Write-Host "  Failed to add password: $pwResult" -ForegroundColor Red
    }
} else {
    Write-Host "  Failed: $bp4" -ForegroundColor Red
}

Write-Host "`n=== Creating Agent Identities ===" -ForegroundColor Cyan

# Create agent identity from the good blueprint
if ($bp1Obj) {
    Write-Host "`n[1/3] Creating agent from 'Good Blueprint'..." -ForegroundColor Yellow
    $agent1Body = @{
        displayName = "EntraLint Test - Good Agent"
        agentIdentityBlueprintId = $bp1Obj.id
        "sponsors@odata.bind" = @($sponsorUri)
    } | ConvertTo-Json -Depth 5

    $agent1 = az rest --method POST `
        --uri "$graphBase/servicePrincipals/microsoft.graph.agentIdentity" `
        --headers "Content-Type=application/json" `
        --body $agent1Body 2>&1
    if ($LASTEXITCODE -eq 0) {
        $agent1Obj = $agent1 | ConvertFrom-Json
        Write-Host "  Created agent: $($agent1Obj.id)" -ForegroundColor Green
    } else {
        Write-Host "  Failed: $agent1" -ForegroundColor Red
    }
}

# Create agent identity from the bad blueprint
if ($bp2Obj) {
    Write-Host "`n[2/3] Creating agent from 'Bad Blueprint'..." -ForegroundColor Yellow
    $agent2Body = @{
        displayName = "EntraLint Test - Bad Agent"
        agentIdentityBlueprintId = $bp2Obj.id
        "sponsors@odata.bind" = @($sponsorUri)
    } | ConvertTo-Json -Depth 5

    $agent2 = az rest --method POST `
        --uri "$graphBase/servicePrincipals/microsoft.graph.agentIdentity" `
        --headers "Content-Type=application/json" `
        --body $agent2Body 2>&1
    if ($LASTEXITCODE -eq 0) {
        $agent2Obj = $agent2 | ConvertFrom-Json
        Write-Host "  Created agent: $($agent2Obj.id)" -ForegroundColor Green
    } else {
        Write-Host "  Failed: $agent2" -ForegroundColor Red
    }
}

# Create agent from overprivileged blueprint
if ($bp3Obj) {
    Write-Host "`n[3/3] Creating agent from 'Overprivileged Blueprint'..." -ForegroundColor Yellow
    $agent3Body = @{
        displayName = "EntraLint Test - Overprivileged Agent"
        agentIdentityBlueprintId = $bp3Obj.id
        "sponsors@odata.bind" = @($sponsorUri)
    } | ConvertTo-Json -Depth 5

    $agent3 = az rest --method POST `
        --uri "$graphBase/servicePrincipals/microsoft.graph.agentIdentity" `
        --headers "Content-Type=application/json" `
        --body $agent3Body 2>&1
    if ($LASTEXITCODE -eq 0) {
        $agent3Obj = $agent3 | ConvertFrom-Json
        Write-Host "  Created agent: $($agent3Obj.id)" -ForegroundColor Green
    } else {
        Write-Host "  Failed: $agent3" -ForegroundColor Red
    }
}

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Blueprints created: 4 (good, bad/no-description, overprivileged, secret-based)"
Write-Host "Agent identities created: 3 (good, bad, overprivileged)"
Write-Host "`nExpected EntraLint findings:" -ForegroundColor Yellow
Write-Host "  agent_006 - Bad blueprint has no description so may lack accountability signals"
Write-Host "  agent_008 - Secret-based blueprint uses password credentials"
Write-Host "  agent_010 - All blueprints may lack inheritablePermissions config"
Write-Host "  agent_012 - Bad blueprint has no description"
Write-Host "`nRun: uv run python -m entralint scan" -ForegroundColor Green
