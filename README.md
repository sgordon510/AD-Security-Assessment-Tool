# AD Security Assessment Tool

**Comprehensive security assessment for Active Directory and Azure AD environments.**

Designed for Windows 11 domain-joined workstations. Generates executive dashboards with security scores, findings, and remediation guidance.

---

## Quick Start (3 Steps)

### 1. Download & Extract
Download and extract to `C:\SecurityAssessment\`

### 2. Run Setup (One Time)
Open PowerShell **as Administrator**:
```powershell
cd C:\SecurityAssessment
.\Setup.ps1
```

### 3. Run Assessment
```powershell
.\Run-Assessment.ps1 -OrgName "Your Company" -CollectData
```

**That's it!** Open `reports\[timestamp]\executive-report.html` in your browser.

---

## What This Tool Does

| Assessment | Detects |
|------------|---------|
| **AD Misconfigurations** | Weak password policies, LDAP signing disabled, unpatched DCs |
| **Privilege Escalation** | Kerberoastable accounts, DCSync rights, dangerous ACLs |
| **Azure AD Security** | MFA gaps, Conditional Access issues, PIM configuration |
| **BloodHound Integration** | Attack paths to Domain Admin |
| **PingCastle Integration** | Comprehensive risk scoring |

---

## Directory Structure

```
C:\SecurityAssessment\
├── Setup.ps1              # One-click prerequisite installer
├── Run-Assessment.ps1     # Main assessment runner
├── package.json           # Bun configuration
├── Scripts/               # Data collection scripts
├── Tools/                 # Assessment engines (TypeScript)
├── Findings/              # Remediation guides
├── docs/                  # Documentation
├── data/                  # Collected data (created on run)
└── reports/               # Generated reports (created on run)
```

---

## Usage Examples

```powershell
# Basic assessment with existing data
.\Run-Assessment.ps1 -OrgName "Contoso Inc"

# Full collection + assessment
.\Run-Assessment.ps1 -OrgName "Contoso Inc" -CollectData

# With Azure AD
.\Run-Assessment.ps1 -OrgName "Contoso Inc" -CollectData -IncludeAzure

# With BloodHound data
.\Run-Assessment.ps1 -OrgName "Contoso Inc" -BloodHoundPath "C:\BloodHound"

# With PingCastle report
.\Run-Assessment.ps1 -OrgName "Contoso Inc" -PingCastlePath "C:\report.xml"
```

---

## Requirements

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1+
- Domain Admin permissions (for data collection)
- Bun runtime (installed by Setup.ps1)

---

## Troubleshooting

### Microsoft Graph Connection Fails

If you see "Failed to connect to Microsoft Graph" when running Azure AD collection:

**Option 1: Use Device Code Authentication**
```powershell
# Run with device code flow (no browser popup required)
.\Run-Assessment.ps1 -OrgName "Your Company" -CollectData -IncludeAzure -UseDeviceCode

# Or run the Azure export directly
.\Scripts\Export-AzureADData.ps1 -UseDeviceCode
```

**Option 2: Manual Module Installation**
```powershell
# Install Microsoft Graph modules as Administrator
Install-Module Microsoft.Graph -Scope AllUsers -Force -AllowClobber

# Test connection manually
Connect-MgGraph -Scopes "User.Read.All"
```

**Option 3: Check Permissions**
- You need **Global Reader** or higher role in Azure AD
- Your organization may require admin consent for the Graph API scopes
- Contact your Azure AD administrator if you see "consent required" errors

**Option 4: Proxy Configuration**
```powershell
# If behind a corporate proxy
$env:HTTPS_PROXY = "http://proxy-server:port"
.\Scripts\Export-AzureADData.ps1
```

---

## Version

**v2.0.1** - Bug Fixes
- Fixed Microsoft Graph connection issues
- Added device code authentication option (-UseDeviceCode)
- Better error messages and troubleshooting guidance
- Auto-install missing Graph sub-modules

**v2.0.0** - Windows 11 Optimized Package
- Flattened directory structure
- One-click setup installer
- Pure PowerShell runner (no WSL required)
