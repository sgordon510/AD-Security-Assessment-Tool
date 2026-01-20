# Export-AzureADData.ps1
# Exports Azure AD configuration for security assessment
# Requires: Microsoft Graph PowerShell module and appropriate permissions

param(
    [string]$OutputPath = ".\data",
    [switch]$UseDeviceCode,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

# Force TLS 1.2 for older PowerShell versions
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Host "`n=== Azure AD Security Assessment Data Export ===" -ForegroundColor Cyan
Write-Host "Output: $OutputPath`n" -ForegroundColor Yellow

# === PREREQUISITE CHECKS ===
Write-Host "[0/6] Checking Prerequisites..." -ForegroundColor Green

# Check for Microsoft Graph module
$graphModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Identity.DirectoryManagement",
    "Microsoft.Graph.Identity.SignIns",
    "Microsoft.Graph.Identity.Governance"
)

$missingModules = @()
foreach ($module in $graphModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        $missingModules += $module
    }
}

if ($missingModules.Count -gt 0) {
    Write-Host "  Missing required modules:" -ForegroundColor Yellow
    foreach ($m in $missingModules) {
        Write-Host "    - $m" -ForegroundColor Yellow
    }
    Write-Host "`n  Installing missing modules..." -ForegroundColor Cyan

    try {
        # Install the main Microsoft.Graph module which includes all sub-modules
        Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        Write-Host "  + Modules installed successfully" -ForegroundColor Green
    } catch {
        Write-Error "Failed to install Microsoft Graph modules: $_"
        Write-Host "`n  Manual fix: Run this command as Administrator:" -ForegroundColor Yellow
        Write-Host "    Install-Module Microsoft.Graph -Scope AllUsers -Force -AllowClobber" -ForegroundColor Cyan
        exit 1
    }
}

Write-Host "  + Microsoft Graph modules available" -ForegroundColor Green

# Import required modules
Write-Host "  Importing modules..." -ForegroundColor Gray
foreach ($module in $graphModules) {
    try {
        Import-Module $module -ErrorAction Stop
    } catch {
        Write-Warning "  Could not import $module - some features may not work"
    }
}
Write-Host "  + Modules imported" -ForegroundColor Green

# Create output directory
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

# Define required scopes
$requiredScopes = @(
    "User.Read.All",
    "UserAuthenticationMethod.Read.All",
    "Policy.Read.All",
    "RoleManagement.Read.Directory",
    "AuditLog.Read.All",
    "Directory.Read.All"
)

# Connect to Microsoft Graph
Write-Host "`n[1/6] Connecting to Microsoft Graph..." -ForegroundColor Green
Write-Host "  Required scopes: $($requiredScopes -join ', ')" -ForegroundColor Gray

# Check if already connected with sufficient scopes
$context = Get-MgContext -ErrorAction SilentlyContinue
if ($context) {
    $hasAllScopes = $true
    foreach ($scope in $requiredScopes) {
        if ($context.Scopes -notcontains $scope) {
            $hasAllScopes = $false
            break
        }
    }

    if ($hasAllScopes) {
        Write-Host "  + Already connected as $($context.Account)" -ForegroundColor Green
    } else {
        Write-Host "  Reconnecting with required scopes..." -ForegroundColor Yellow
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        $context = $null
    }
}

if (-not $context -or -not $hasAllScopes) {
    try {
        if ($UseDeviceCode) {
            # Device code flow - works in environments where interactive auth fails
            Write-Host "  Using device code authentication..." -ForegroundColor Cyan
            Write-Host "  (A browser window will NOT open - follow the instructions below)" -ForegroundColor Yellow
            Connect-MgGraph -Scopes $requiredScopes -UseDeviceCode -ErrorAction Stop
        } else {
            # Interactive authentication (default)
            Write-Host "  Opening browser for authentication..." -ForegroundColor Cyan
            Write-Host "  (If no browser opens, re-run with -UseDeviceCode flag)" -ForegroundColor Gray
            Connect-MgGraph -Scopes $requiredScopes -ErrorAction Stop
        }

        $context = Get-MgContext
        Write-Host "  + Connected successfully as $($context.Account)" -ForegroundColor Green
        Write-Host "  + Tenant: $($context.TenantId)" -ForegroundColor Green
    } catch {
        Write-Host "`n  CONNECTION FAILED" -ForegroundColor Red
        Write-Host "  Error: $_" -ForegroundColor Red

        Write-Host "`n  Troubleshooting steps:" -ForegroundColor Yellow
        Write-Host "  1. If browser didn't open, try: .\Export-AzureADData.ps1 -UseDeviceCode" -ForegroundColor Cyan
        Write-Host "  2. Ensure you have Global Reader or higher permissions in Azure AD" -ForegroundColor Cyan
        Write-Host "  3. Check if your organization requires admin consent for these scopes" -ForegroundColor Cyan
        Write-Host "  4. Try running: Connect-MgGraph -Scopes 'User.Read.All' manually to test" -ForegroundColor Cyan
        Write-Host "  5. If behind a proxy, configure: `$env:HTTPS_PROXY = 'http://proxy:port'" -ForegroundColor Cyan

        exit 1
    }
}

$azureADData = @{
    collectionDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    tenantId = (Get-MgOrganization).Id
}

# === 1. USER DATA ===
Write-Host "`n[2/6] Collecting User Data..." -ForegroundColor Green

$users = @()
$allUsers = Get-MgUser -All -Property `
    UserPrincipalName, DisplayName, UserType, AccountEnabled, SignInActivity, CreatedDateTime, AssignedLicenses

$totalUsers = $allUsers.Count
$counter = 0

foreach ($user in $allUsers) {
    $counter++
    if ($counter % 100 -eq 0) {
        Write-Progress -Activity "Processing users" -Status "$counter of $totalUsers" -PercentComplete (($counter / $totalUsers) * 100)
    }

    # Check MFA status
    try {
        $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction SilentlyContinue
        $mfaEnabled = ($authMethods.Count -gt 1)  # More than just password
    } catch {
        $mfaEnabled = $false
    }

    # Check assigned roles
    try {
        $roleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($user.Id)'" -ErrorAction SilentlyContinue
        $assignedRoles = $roleAssignments | ForEach-Object {
            $roleId = $_.RoleDefinitionId
            $role = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $roleId -ErrorAction SilentlyContinue
            $role.DisplayName
        }
    } catch {
        $assignedRoles = @()
    }

    $users += @{
        userPrincipalName = $user.UserPrincipalName
        displayName = $user.DisplayName
        userType = $user.UserType
        accountEnabled = $user.AccountEnabled
        mfaStatus = if ($mfaEnabled) { "enabled" } else { "disabled" }
        lastSignIn = $user.SignInActivity.LastSignInDateTime
        createdDateTime = $user.CreatedDateTime
        assignedRoles = $assignedRoles
        hasLicense = ($user.AssignedLicenses.Count -gt 0)
    }
}

Write-Progress -Activity "Processing users" -Completed
$azureADData.users = $users
Write-Host "  + Processed $($users.Count) users" -ForegroundColor Green

# === 2. CONDITIONAL ACCESS POLICIES ===
Write-Host "`n[3/6] Collecting Conditional Access Policies..." -ForegroundColor Green

try {
    $caPolicies = Get-MgIdentityConditionalAccessPolicy | Select-Object `
        @{Name='name';Expression={$_.DisplayName}},
        State,
        Conditions,
        GrantControls,
        SessionControls

    $azureADData.conditionalAccessPolicies = $caPolicies
    Write-Host "  + Found $($caPolicies.Count) policies" -ForegroundColor Green
} catch {
    Write-Warning "  Unable to retrieve Conditional Access policies (requires Azure AD Premium)"
    $azureADData.conditionalAccessPolicies = @()
}

# === 3. PIM CONFIGURATION ===
Write-Host "`n[4/6] Checking PIM Configuration..." -ForegroundColor Green

try {
    $pimConfig = @()
    $roles = Get-MgRoleManagementDirectoryRoleDefinition -All

    foreach ($role in $roles | Where-Object { $_.DisplayName -match "Administrator|Admin" } | Select-Object -First 20) {
        try {
            $assignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$($role.Id)'" -All

            $activeCount = 0
            $eligibleCount = 0

            foreach ($assignment in $assignments) {
                # Check if eligible or active (this is simplified - full PIM requires additional API calls)
                if ($assignment.DirectoryScopeId -eq "/") {
                    $activeCount++
                }
            }

            if ($activeCount -gt 0) {
                $pimConfig += @{
                    roleName = $role.DisplayName
                    activeAssignments = $activeCount
                    eligibleAssignments = $eligibleCount  # Would need PIM API for accurate count
                }
            }
        } catch {
            # Skip roles we can't query
        }
    }

    $azureADData.pimConfiguration = $pimConfig
    Write-Host "  + Analyzed $($pimConfig.Count) privileged roles" -ForegroundColor Green
} catch {
    Write-Warning "  PIM data unavailable (requires Azure AD Premium P2)"
    $azureADData.pimConfiguration = @()
}

# === 4. SECURITY DEFAULTS ===
Write-Host "`n[5/6] Checking Security Settings..." -ForegroundColor Green

try {
    $securityDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
    $azureADData.securityDefaults = $securityDefaults.IsEnabled
    Write-Host "  Security Defaults: $($securityDefaults.IsEnabled)" -ForegroundColor Cyan
} catch {
    $azureADData.securityDefaults = $null
    Write-Warning "  Unable to check Security Defaults"
}

# Check for legacy auth (simplified - would need sign-in logs for accurate detection)
$azureADData.legacyAuthEnabled = $null  # Requires analyzing sign-in logs

# Password protection settings (not available via Graph API - portal only)
$azureADData.passwordProtection = @{
    customBannedPasswords = $null
    enabledOnPremises = $null
}

# === 5. STATISTICS ===
Write-Host "`n[6/6] Generating Statistics..." -ForegroundColor Green

$stats = @{
    totalUsers = $users.Count
    memberUsers = ($users | Where-Object {$_.userType -eq "Member"}).Count
    guestUsers = ($users | Where-Object {$_.userType -eq "Guest"}).Count
    enabledUsers = ($users | Where-Object {$_.accountEnabled}).Count
    usersWithMFA = ($users | Where-Object {$_.mfaStatus -eq "enabled"}).Count
    privilegedRoles = $pimConfig.Count
    caPolicies = $azureADData.conditionalAccessPolicies.Count
}

$mfaPercentage = if ($stats.memberUsers -gt 0) {
    [math]::Round(($stats.usersWithMFA / $stats.memberUsers) * 100, 1)
} else { 0 }

Write-Host "  Total Users: $($stats.totalUsers) ($($stats.memberUsers) members, $($stats.guestUsers) guests)" -ForegroundColor Cyan
Write-Host "  MFA Adoption: $mfaPercentage% ($($stats.usersWithMFA) of $($stats.memberUsers) members)" -ForegroundColor Cyan
Write-Host "  Conditional Access Policies: $($stats.caPolicies)" -ForegroundColor Cyan
Write-Host "  Privileged Roles Analyzed: $($stats.privilegedRoles)" -ForegroundColor Cyan

# === 6. SAVE OUTPUT ===
$azureADData | ConvertTo-Json -Depth 15 | Out-File "$OutputPath\azure-ad.json" -Encoding UTF8

# Secure permissions
icacls $OutputPath /inheritance:r /grant:r "$env:USERNAME:(OI)(CI)F" | Out-Null

# Disconnect
Disconnect-MgGraph | Out-Null

Write-Host "`n=== Export Complete ===" -ForegroundColor Green
Write-Host "`nOutput file:" -ForegroundColor Yellow
Write-Host "  - $OutputPath\azure-ad.json" -ForegroundColor White

Write-Host "`nIMPORTANT:" -ForegroundColor Red
Write-Host "  This file contains sensitive organizational data" -ForegroundColor Yellow
Write-Host "  - Encrypt before transferring" -ForegroundColor Yellow
Write-Host "  - Delete securely after assessment" -ForegroundColor Yellow
Write-Host "  - Never commit to version control`n" -ForegroundColor Yellow
