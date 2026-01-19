# Setup.ps1 - One-Click Prerequisites Installer for AD Security Assessment Tool
# Run this script as Administrator on a Windows 11 domain-joined workstation

#Requires -RunAsAdministrator

param(
    [switch]$SkipBun,
    [switch]$SkipRSAT,
    [switch]$SkipGraph,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message, [string]$Status = "INFO")
    $colors = @{
        "INFO" = "Cyan"
        "SUCCESS" = "Green"
        "WARNING" = "Yellow"
        "ERROR" = "Red"
        "SKIP" = "DarkGray"
    }
    Write-Host "[$Status] " -ForegroundColor $colors[$Status] -NoNewline
    Write-Host $Message
}

function Test-AdminPrivileges {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Banner
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "   AD Security Assessment Tool - Windows 11 Setup" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# Check Windows version
$osVersion = [System.Environment]::OSVersion.Version
Write-Step "Detected Windows $($osVersion.Major).$($osVersion.Minor) Build $($osVersion.Build)"

if ($osVersion.Build -lt 22000) {
    Write-Step "This tool is optimized for Windows 11 (Build 22000+). You may experience issues." "WARNING"
}

# Check domain membership
try {
    $domainInfo = Get-WmiObject -Class Win32_ComputerSystem
    if ($domainInfo.PartOfDomain) {
        Write-Step "Domain-joined: $($domainInfo.Domain)" "SUCCESS"
    } else {
        Write-Step "This machine is NOT domain-joined. AD data collection will fail." "WARNING"
        Write-Step "You can still run the assessment with pre-collected data files." "INFO"
    }
} catch {
    Write-Step "Unable to determine domain status" "WARNING"
}

Write-Host ""
Write-Host "--- Installing Prerequisites ---" -ForegroundColor Yellow
Write-Host ""

# === 1. RSAT Active Directory Tools ===
if (-not $SkipRSAT) {
    Write-Step "Checking RSAT Active Directory Tools..."

    $rsatInstalled = Get-WindowsCapability -Online -Name "Rsat.ActiveDirectory*" |
                     Where-Object { $_.State -eq "Installed" }

    if ($rsatInstalled) {
        Write-Step "RSAT AD Tools already installed" "SUCCESS"
    } else {
        Write-Step "Installing RSAT Active Directory Tools..."
        try {
            Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" | Out-Null
            Write-Step "RSAT AD Tools installed successfully" "SUCCESS"
        } catch {
            Write-Step "Failed to install RSAT. Error: $($_.Exception.Message)" "ERROR"
            Write-Step "Try manually: Settings > Apps > Optional Features > Add RSAT" "INFO"
        }
    }
} else {
    Write-Step "Skipping RSAT installation (--SkipRSAT)" "SKIP"
}

# === 2. Bun Runtime ===
if (-not $SkipBun) {
    Write-Step "Checking Bun runtime..."

    $bunPath = Get-Command bun -ErrorAction SilentlyContinue

    if ($bunPath -and -not $Force) {
        $bunVersion = & bun --version 2>$null
        Write-Step "Bun $bunVersion already installed at $($bunPath.Source)" "SUCCESS"
    } else {
        Write-Step "Installing Bun runtime..."
        try {
            $installScript = Invoke-RestMethod -Uri "https://bun.sh/install.ps1"
            Invoke-Expression $installScript

            $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
                        [System.Environment]::GetEnvironmentVariable("Path", "User")

            $bunVersion = & bun --version 2>$null
            if ($bunVersion) {
                Write-Step "Bun $bunVersion installed successfully" "SUCCESS"
            } else {
                Write-Step "Bun installed. Please restart your terminal to use it." "WARNING"
            }
        } catch {
            Write-Step "Failed to install Bun. Error: $($_.Exception.Message)" "ERROR"
            Write-Step "Manual install: irm bun.sh/install.ps1 | iex" "INFO"
        }
    }
} else {
    Write-Step "Skipping Bun installation (--SkipBun)" "SKIP"
}

# === 3. Microsoft Graph PowerShell (Optional) ===
if (-not $SkipGraph) {
    Write-Step "Checking Microsoft Graph PowerShell module..."

    $graphModule = Get-Module -ListAvailable -Name "Microsoft.Graph.Authentication" -ErrorAction SilentlyContinue

    if ($graphModule) {
        Write-Step "Microsoft Graph module v$($graphModule.Version) already installed" "SUCCESS"
    } else {
        Write-Step "Installing Microsoft Graph PowerShell module (for Azure AD)..."
        try {
            Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
            Write-Step "Microsoft Graph module installed successfully" "SUCCESS"
        } catch {
            Write-Step "Failed to install Graph module. Error: $($_.Exception.Message)" "WARNING"
            Write-Step "Azure AD assessment will not be available without this module" "INFO"
        }
    }
} else {
    Write-Step "Skipping Microsoft Graph installation (--SkipGraph)" "SKIP"
}

# === 4. Create directories ===
Write-Step "Creating directory structure..."
$dirs = @("data", "reports")
foreach ($dir in $dirs) {
    $path = Join-Path $PSScriptRoot $dir
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
}
Write-Step "Directory structure ready" "SUCCESS"

# === 5. Set execution policy ===
Write-Step "Configuring PowerShell execution policy..."
try {
    $currentPolicy = Get-ExecutionPolicy -Scope CurrentUser
    if ($currentPolicy -eq "Restricted") {
        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
        Write-Step "Execution policy set to RemoteSigned" "SUCCESS"
    } else {
        Write-Step "Execution policy already allows scripts ($currentPolicy)" "SUCCESS"
    }
} catch {
    Write-Step "Could not set execution policy. Scripts may not run." "WARNING"
}

# === 6. Unblock scripts ===
Write-Step "Unblocking assessment scripts..."
Get-ChildItem -Path $PSScriptRoot -Recurse -Include "*.ps1", "*.ts" |
    ForEach-Object { Unblock-File -Path $_.FullName -ErrorAction SilentlyContinue }
Write-Step "Scripts unblocked" "SUCCESS"

# === Summary ===
Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "   Setup Complete!" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host ""
Write-Host "  1. Collect AD data (run as Domain Admin):" -ForegroundColor White
Write-Host "     .\Scripts\Export-ADData.ps1 -OutputPath .\data" -ForegroundColor Cyan
Write-Host ""
Write-Host "  2. Collect Azure AD data (optional):" -ForegroundColor White
Write-Host "     .\Scripts\Export-AzureADData.ps1 -OutputPath .\data" -ForegroundColor Cyan
Write-Host ""
Write-Host "  3. Run the assessment:" -ForegroundColor White
Write-Host "     .\Run-Assessment.ps1" -ForegroundColor Cyan
Write-Host ""
Write-Host "  4. View results:" -ForegroundColor White
Write-Host "     Open reports\[timestamp]\executive-report.html in your browser" -ForegroundColor Cyan
Write-Host ""

if (-not (Get-Command bun -ErrorAction SilentlyContinue)) {
    Write-Host "NOTE: Please restart your terminal/PowerShell for Bun to be available." -ForegroundColor Yellow
    Write-Host ""
}
