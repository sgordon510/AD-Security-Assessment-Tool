# Run-Assessment.ps1 - Master Assessment Runner for Windows 11
# Pure PowerShell wrapper - no WSL or Git Bash required

param(
    [string]$OrgName = "Security Assessment",
    [string]$DataPath = ".\data",
    [string]$OutputPath = "",
    [switch]$CollectData,
    [switch]$IncludeAzure,
    [switch]$IncludeACLs,
    [switch]$UseDeviceCode,
    [string]$BloodHoundPath = "",
    [string]$PingCastlePath = "",
    [switch]$Help
)

$ErrorActionPreference = "Stop"
$ScriptRoot = $PSScriptRoot

if ($Help) {
    Write-Host @"

================================================================
   AD Security Assessment Tool - Windows 11
================================================================

USAGE:
    .\Run-Assessment.ps1 [options]

OPTIONS:
    -OrgName <string>       Organization name for reports (default: "Security Assessment")
    -DataPath <string>      Path to data files (default: .\data)
    -OutputPath <string>    Output directory for reports (default: .\reports\YYYYMMDD-HHMM)
    -CollectData            Run data collection before assessment
    -IncludeAzure           Include Azure AD data collection
    -IncludeACLs            Include ACL analysis (slower)
    -UseDeviceCode          Use device code auth for Azure AD (when browser popup fails)
    -BloodHoundPath <string> Path to BloodHound JSON files
    -PingCastlePath <string> Path to PingCastle XML report
    -Help                   Show this help message

EXAMPLES:
    .\Run-Assessment.ps1 -OrgName "Contoso Inc"
    .\Run-Assessment.ps1 -OrgName "Contoso Inc" -CollectData -IncludeAzure
    .\Run-Assessment.ps1 -OrgName "Contoso Inc" -CollectData -IncludeAzure -UseDeviceCode
    .\Run-Assessment.ps1 -OrgName "Contoso Inc" -BloodHoundPath ".\data\bloodhound"

"@
    exit 0
}

function Write-Banner {
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "   AD Security Assessment Tool" -ForegroundColor Cyan
    Write-Host "   Organization: $OrgName" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step {
    param([string]$Message, [string]$Status = "INFO")
    $colors = @{ "INFO" = "Cyan"; "SUCCESS" = "Green"; "WARNING" = "Yellow"; "ERROR" = "Red"; "RUNNING" = "Magenta" }
    $symbols = @{ "INFO" = "i"; "SUCCESS" = "+"; "WARNING" = "!"; "ERROR" = "X"; "RUNNING" = ">" }
    Write-Host "[$($symbols[$Status])] " -ForegroundColor $colors[$Status] -NoNewline
    Write-Host $Message
}

function Test-BunInstalled {
    $bun = Get-Command bun -ErrorAction SilentlyContinue
    if (-not $bun) {
        Write-Step "Bun runtime not found. Please run .\Setup.ps1 first." "ERROR"
        exit 1
    }
    return $true
}

function Invoke-DataCollection {
    Write-Host ""
    Write-Host "--- Data Collection Phase ---" -ForegroundColor Yellow
    Write-Host ""

    if (-not (Test-Path $DataPath)) {
        New-Item -ItemType Directory -Path $DataPath -Force | Out-Null
    }

    Write-Step "Collecting Active Directory data..." "RUNNING"
    $adScript = Join-Path $ScriptRoot "Scripts\Export-ADData.ps1"

    if (Test-Path $adScript) {
        try {
            if ($IncludeACLs) {
                & $adScript -OutputPath $DataPath -IncludeACLs
            } else {
                & $adScript -OutputPath $DataPath
            }
            Write-Step "AD data collection complete" "SUCCESS"
        } catch {
            Write-Step "AD data collection failed: $($_.Exception.Message)" "ERROR"
        }
    } else {
        Write-Step "Export-ADData.ps1 not found" "ERROR"
    }

    if ($IncludeAzure) {
        Write-Step "Collecting Azure AD data..." "RUNNING"
        $azureScript = Join-Path $ScriptRoot "Scripts\Export-AzureADData.ps1"

        if (Test-Path $azureScript) {
            try {
                if ($UseDeviceCode) {
                    & $azureScript -OutputPath $DataPath -UseDeviceCode
                } else {
                    & $azureScript -OutputPath $DataPath
                }
                Write-Step "Azure AD data collection complete" "SUCCESS"
            } catch {
                Write-Step "Azure AD data collection failed: $($_.Exception.Message)" "WARNING"
                Write-Step "TIP: If authentication failed, try running with -UseDeviceCode flag" "INFO"
            }
        }
    }
}

function Invoke-Assessment {
    Write-Host ""
    Write-Host "--- Assessment Phase ---" -ForegroundColor Yellow
    Write-Host ""

    if ([string]::IsNullOrEmpty($OutputPath)) {
        $timestamp = Get-Date -Format "yyyyMMdd-HHmm"
        $OutputPath = Join-Path $ScriptRoot "reports\$timestamp"
    }

    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    Write-Step "Output directory: $OutputPath" "INFO"

    $toolsDir = Join-Path $ScriptRoot "Tools"
    $runScript = Join-Path $toolsDir "RunFullAssessment.ts"

    $bunArgs = @("run", $runScript, "--org", $OrgName, "--output", $OutputPath)

    $adConfig = Join-Path $DataPath "ad-config.json"
    $identityData = Join-Path $DataPath "ad-identity.json"
    $azureData = Join-Path $DataPath "azure-ad.json"

    if (Test-Path $adConfig) {
        $bunArgs += @("--ad-config", $adConfig)
        Write-Step "Found: ad-config.json" "SUCCESS"
    } else {
        Write-Step "Not found: ad-config.json" "WARNING"
    }

    if (Test-Path $identityData) {
        $bunArgs += @("--identity", $identityData)
        Write-Step "Found: ad-identity.json" "SUCCESS"
    } else {
        Write-Step "Not found: ad-identity.json" "WARNING"
    }

    if (Test-Path $azureData) {
        $bunArgs += @("--azure", $azureData)
        Write-Step "Found: azure-ad.json" "SUCCESS"
    }

    if (-not [string]::IsNullOrEmpty($BloodHoundPath) -and (Test-Path $BloodHoundPath)) {
        $bunArgs += @("--bloodhound", $BloodHoundPath)
        Write-Step "Found: BloodHound data" "SUCCESS"
    }

    if (-not [string]::IsNullOrEmpty($PingCastlePath) -and (Test-Path $PingCastlePath)) {
        $bunArgs += @("--pingcastle", $PingCastlePath)
        Write-Step "Found: PingCastle report" "SUCCESS"
    }

    Write-Host ""
    Write-Step "Running security assessment with Bun..." "RUNNING"
    Write-Host ""

    try {
        & bun $bunArgs
        Write-Step "Assessment completed successfully" "SUCCESS"
    } catch {
        Write-Step "Assessment failed: $($_.Exception.Message)" "ERROR"
        exit 1
    }

    return $OutputPath
}

function Show-Results {
    param([string]$ReportPath)

    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host "   Assessment Complete!" -ForegroundColor Green
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host ""

    $execReport = Join-Path $ReportPath "executive-report.html"

    Write-Host "Reports generated at:" -ForegroundColor Yellow
    Write-Host "  $ReportPath" -ForegroundColor Cyan
    Write-Host ""

    if (Test-Path $execReport) {
        Write-Host "Executive Dashboard:" -ForegroundColor Yellow
        Write-Host "  $execReport" -ForegroundColor Cyan
        Write-Host ""

        $openReport = Read-Host "Open executive report in browser? (Y/n)"
        if ($openReport -ne "n" -and $openReport -ne "N") {
            Start-Process $execReport
        }
    }

    Write-Host ""
    Write-Host "Next Steps:" -ForegroundColor Yellow
    Write-Host "  1. Review the executive dashboard with leadership"
    Write-Host "  2. Prioritize CRITICAL and HIGH severity findings"
    Write-Host "  3. Assign remediation owners"
    Write-Host "  4. Schedule follow-up assessment in 30 days"
    Write-Host ""
}

# === MAIN ===
Write-Banner
Test-BunInstalled | Out-Null

if ($CollectData) {
    Invoke-DataCollection
}

$reportPath = Invoke-Assessment
Show-Results -ReportPath $reportPath
