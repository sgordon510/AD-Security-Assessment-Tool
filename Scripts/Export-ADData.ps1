# Export-ADData.ps1
# Exports Active Directory configuration for security assessment
# Requires: Domain Admin or equivalent read access

param(
    [string]$OutputPath = ".\data",
    [switch]$IncludeACLs = $false
)

# Create output directory
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

Write-Host "`n=== AD Security Assessment Data Export ===" -ForegroundColor Cyan
Write-Host "Output: $OutputPath`n" -ForegroundColor Yellow

try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Error "Active Directory module not found. Run on domain-joined system with RSAT installed."
    exit 1
}

# === 1. AD CONFIGURATION ===
Write-Host "[1/4] Exporting AD Configuration..." -ForegroundColor Green

$domain = Get-ADDomain
$adConfig = @{
    domain = $domain.DNSRoot
    collectionDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Password Policy
    passwordPolicy = Get-ADDefaultDomainPasswordPolicy | Select-Object `
        @{Name='minimumPasswordLength';Expression={$_.MinPasswordLength}},
        @{Name='passwordComplexity';Expression={$_.ComplexityEnabled}},
        @{Name='lockoutThreshold';Expression={$_.LockoutThreshold}},
        @{Name='maximumPasswordAge';Expression={$_.MaxPasswordAge.Days}},
        @{Name='minimumPasswordAge';Expression={$_.MinPasswordAge.Days}}

    # LDAP Settings (requires checking on DCs)
    ldapSettings = @{
        ldapSigning = $null  # Set manually after checking
        channelBinding = $null
        ssl = $null
    }

    # Domain Controllers
    domainControllers = Get-ADDomainController -Filter * | ForEach-Object {
        try {
            $hotfix = Get-HotFix -ComputerName $_.HostName |
                      Sort-Object InstalledOn -Descending |
                      Select-Object -First 1
            $lastPatch = if ($hotfix) { $hotfix.InstalledOn.ToString("yyyy-MM-dd") } else { "Unknown" }
        } catch {
            $lastPatch = "Unable to query"
        }

        @{
            hostname = $_.HostName
            osVersion = $_.OperatingSystem
            lastPatchDate = $lastPatch
        }
    }

    # Service Accounts (accounts with SPNs)
    serviceAccounts = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties `
        ServicePrincipalName, PasswordLastSet, DoesNotRequirePreAuth, AdminCount, Enabled |
        Where-Object {$_.Enabled} |
        Select-Object `
            @{Name='name';Expression={$_.SamAccountName}},
            @{Name='passwordLastSet';Expression={$_.PasswordLastSet.ToString("yyyy-MM-dd")}},
            @{Name='kerberosPreAuthRequired';Expression={-not $_.DoesNotRequirePreAuth}},
            AdminCount
}

# Manually check LDAP settings on a DC
Write-Host "  Checking LDAP settings on DC..." -ForegroundColor Yellow
try {
    $dc = (Get-ADDomainController).HostName
    $ldapReg = Invoke-Command -ComputerName $dc -ScriptBlock {
        Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue
    }
    $adConfig.ldapSettings.ldapSigning = ($ldapReg.LDAPServerIntegrity -eq 2)
} catch {
    Write-Warning "  Unable to query LDAP settings remotely"
}

$adConfig | ConvertTo-Json -Depth 10 | Out-File "$OutputPath\ad-config.json" -Encoding UTF8
Write-Host "  + Saved: ad-config.json" -ForegroundColor Green

# === 2. IDENTITY & PRIVILEGE DATA ===
Write-Host "`n[2/4] Exporting Identity & Privilege Data..." -ForegroundColor Green

$identityData = @{
    collectionDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # All user accounts
    accounts = Get-ADUser -Filter * -Properties `
        MemberOf, LastLogonDate, PasswordLastSet, AdminCount, ServicePrincipalName, Enabled, Description |
        Select-Object `
            SamAccountName,
            DistinguishedName,
            @{Name='memberOf';Expression={$_.MemberOf}},
            @{Name='lastLogon';Expression={if($_.LastLogonDate){$_.LastLogonDate.ToString("yyyy-MM-dd")}else{$null}}},
            @{Name='pwdLastSet';Expression={if($_.PasswordLastSet){$_.PasswordLastSet.ToString("yyyy-MM-dd")}else{$null}}},
            AdminCount,
            @{Name='servicePrincipalNames';Expression={$_.ServicePrincipalName}},
            Enabled,
            Description

    # Privileged groups
    groups = Get-ADGroup -Filter {
        Name -like "*Admin*" -or
        Name -like "*Operator*" -or
        Name -eq "Enterprise Admins" -or
        Name -eq "Schema Admins" -or
        Name -eq "Domain Admins" -or
        Name -eq "Account Operators" -or
        Name -eq "Backup Operators" -or
        Name -eq "Server Operators"
    } -Properties Members, Description |
    Select-Object `
        Name,
        @{Name='members';Expression={$_.Members}},
        Description
}

# === 3. OPTIONAL: ACL EXPORT ===
if ($IncludeACLs) {
    Write-Host "  Exporting ACLs (this may take a while)..." -ForegroundColor Yellow

    $aclExport = @()
    $criticalOUs = @(
        $domain.DistinguishedName,  # Root domain
        "CN=Users,$($domain.DistinguishedName)",
        "OU=Domain Controllers,$($domain.DistinguishedName)"
    )

    foreach ($ou in $criticalOUs) {
        try {
            $acl = Get-Acl "AD:$ou"
            foreach ($access in $acl.Access) {
                if ($access.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteDacl|WriteOwner|AddMember") {
                    $aclExport += @{
                        objectDN = $ou
                        trustee = $access.IdentityReference.Value
                        rights = @($access.ActiveDirectoryRights.ToString())
                        isInherited = $access.IsInherited
                    }
                }
            }
        } catch {
            Write-Warning "  Unable to read ACL for $ou"
        }
    }

    $identityData.acls = $aclExport
    Write-Host "  + Exported $($aclExport.Count) ACL entries" -ForegroundColor Green
}

$identityData | ConvertTo-Json -Depth 15 | Out-File "$OutputPath\ad-identity.json" -Encoding UTF8
Write-Host "  + Saved: ad-identity.json" -ForegroundColor Green

# === 4. STATISTICS ===
Write-Host "`n[3/4] Generating Statistics..." -ForegroundColor Green
$stats = @{
    totalUsers = $identityData.accounts.Count
    enabledUsers = ($identityData.accounts | Where-Object {$_.Enabled}).Count
    privilegedGroups = $identityData.groups.Count
    domainControllers = $adConfig.domainControllers.Count
    serviceAccounts = $adConfig.serviceAccounts.Count
}

Write-Host "  Users: $($stats.totalUsers) total, $($stats.enabledUsers) enabled" -ForegroundColor Cyan
Write-Host "  Privileged Groups: $($stats.privilegedGroups)" -ForegroundColor Cyan
Write-Host "  Domain Controllers: $($stats.domainControllers)" -ForegroundColor Cyan
Write-Host "  Service Accounts: $($stats.serviceAccounts)" -ForegroundColor Cyan

# === 5. SECURE OUTPUT ===
Write-Host "`n[4/4] Securing Output Directory..." -ForegroundColor Green
icacls $OutputPath /inheritance:r /grant:r "$env:USERNAME:(OI)(CI)F" | Out-Null
Write-Host "  + Restricted permissions to current user" -ForegroundColor Green

Write-Host "`n=== Export Complete ===" -ForegroundColor Green
Write-Host "`nOutput files:" -ForegroundColor Yellow
Write-Host "  - $OutputPath\ad-config.json" -ForegroundColor White
Write-Host "  - $OutputPath\ad-identity.json" -ForegroundColor White

Write-Host "`nIMPORTANT:" -ForegroundColor Red
Write-Host "  These files contain sensitive organizational data" -ForegroundColor Yellow
Write-Host "  - Encrypt before transferring" -ForegroundColor Yellow
Write-Host "  - Delete securely after assessment" -ForegroundColor Yellow
Write-Host "  - Never commit to version control`n" -ForegroundColor Yellow

Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Run SharpHound (optional): .\SharpHound.exe -c All" -ForegroundColor White
Write-Host "  2. Run PingCastle (optional): .\PingCastle.exe --healthcheck" -ForegroundColor White
Write-Host "  3. Export Azure AD data (if hybrid): .\Scripts\Export-AzureADData.ps1" -ForegroundColor White
Write-Host "  4. Run assessment: .\Run-Assessment.ps1`n" -ForegroundColor White
