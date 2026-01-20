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

## BloodHound Integration

[BloodHound](https://github.com/BloodHoundAD/BloodHound) is a tool for analyzing Active Directory attack paths. This assessment tool can parse BloodHound data to identify privilege escalation risks.

### Step 1: Download BloodHound & SharpHound

1. Download BloodHound from the [official releases](https://github.com/BloodHoundAD/BloodHound/releases)
2. Download SharpHound (the data collector) from [BloodHound releases](https://github.com/BloodHoundAD/SharpHound/releases)
3. Extract both to a folder (e.g., `C:\BloodHound\`)

### Step 2: Run SharpHound to Collect Data

On a domain-joined machine **as a Domain User** (Domain Admin not required):

```powershell
# Basic collection (recommended)
.\SharpHound.exe -c All

# Or with specific output folder
.\SharpHound.exe -c All --outputdirectory C:\BloodHound\Data

# Stealth mode (slower but less detectable)
.\SharpHound.exe -c All --stealth
```

SharpHound creates a ZIP file containing JSON files:
```
20240115120000_BloodHound.zip
├── 20240115120000_users.json
├── 20240115120000_computers.json
├── 20240115120000_groups.json
├── 20240115120000_domains.json
└── 20240115120000_gpos.json
```

### Step 3: Extract and Use with Assessment Tool

```powershell
# Extract the SharpHound ZIP
Expand-Archive -Path "20240115120000_BloodHound.zip" -DestinationPath "C:\BloodHound\Data"

# Run assessment with BloodHound data
.\Run-Assessment.ps1 -OrgName "Your Company" -BloodHoundPath "C:\BloodHound\Data"
```

### What BloodHound Analysis Detects

| Finding | Severity | Description |
|---------|----------|-------------|
| Kerberoastable Accounts | CRITICAL/MEDIUM | Service accounts with SPNs vulnerable to offline cracking |
| AS-REP Roastable Accounts | CRITICAL | Accounts without Kerberos pre-auth |
| Unconstrained Delegation | HIGH | Computers that can impersonate any user |
| LAPS Coverage Gaps | HIGH/MEDIUM | Computers without local admin password management |
| Dangerous AD Permissions | HIGH | GenericAll, WriteDacl, etc. on sensitive objects |
| Dormant Admin Accounts | HIGH | Privileged accounts inactive for 90+ days |
| Large Privileged Groups | MEDIUM | Groups with excessive membership |

---

## PingCastle Integration

[PingCastle](https://www.pingcastle.com/) is a comprehensive AD security assessment tool that produces a risk score. This tool can parse PingCastle reports to include findings in the executive dashboard.

### Step 1: Download PingCastle

1. Download from [pingcastle.com/download](https://www.pingcastle.com/download/)
2. Extract to a folder (e.g., `C:\PingCastle\`)

PingCastle is free for basic use. Enterprise features require a license.

### Step 2: Run PingCastle Health Check

On a domain-joined machine **as a Domain Admin**:

```powershell
cd C:\PingCastle

# Basic health check (auto-detects domain)
.\PingCastle.exe --healthcheck

# Specify domain explicitly
.\PingCastle.exe --healthcheck --server contoso.com

# Generate XML report (recommended for parsing)
.\PingCastle.exe --healthcheck --server contoso.com --level Full
```

PingCastle creates reports in the current directory:
```
ad_hc_contoso.com.html    # Human-readable HTML report
ad_hc_contoso.com.xml     # Machine-readable XML report (preferred)
```

### Step 3: Use with Assessment Tool

```powershell
# Using XML report (recommended - more detailed parsing)
.\Run-Assessment.ps1 -OrgName "Your Company" -PingCastlePath "C:\PingCastle\ad_hc_contoso.com.xml"

# Using HTML report (also supported)
.\Run-Assessment.ps1 -OrgName "Your Company" -PingCastlePath "C:\PingCastle\ad_hc_contoso.com.html"
```

### PingCastle Risk Score Mapping

| PingCastle Points | This Tool's Severity |
|-------------------|---------------------|
| 50+ points | CRITICAL |
| 30-49 points | HIGH |
| 15-29 points | MEDIUM |
| 5-14 points | LOW |
| <5 points | INFO |

### What PingCastle Detects

PingCastle analyzes 100+ security rules across categories:
- **Stale Objects**: Dormant accounts, old computers, expired passwords
- **Privileged Accounts**: Excessive admins, service accounts, delegation issues
- **Trusts**: External trust risks, SID history abuse
- **Anomalies**: AdminSDHolder, schema modifications, GPO issues
- **Vulnerabilities**: Missing patches, weak protocols, certificate issues

---

## Full Assessment Example

Run a comprehensive assessment with all data sources:

```powershell
# 1. Collect AD data
.\Run-Assessment.ps1 -OrgName "Contoso Inc" -CollectData

# 2. Run SharpHound separately (as regular domain user)
cd C:\BloodHound
.\SharpHound.exe -c All --outputdirectory C:\BloodHound\Data

# 3. Run PingCastle separately (as Domain Admin)
cd C:\PingCastle
.\PingCastle.exe --healthcheck

# 4. Run full assessment with all data sources
cd C:\SecurityAssessment
.\Run-Assessment.ps1 -OrgName "Contoso Inc" `
    -CollectData `
    -IncludeAzure `
    -BloodHoundPath "C:\BloodHound\Data" `
    -PingCastlePath "C:\PingCastle\ad_hc_contoso.com.xml"
```

---

## Requirements

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1+
- Domain Admin permissions (for data collection)
- Bun runtime (installed by Setup.ps1)

### Optional Tool Requirements

| Tool | Required Permissions | Download |
|------|---------------------|----------|
| **SharpHound** | Domain User (minimum) | [GitHub Releases](https://github.com/BloodHoundAD/SharpHound/releases) |
| **PingCastle** | Domain Admin (recommended) | [pingcastle.com](https://www.pingcastle.com/download/) |
| **Azure AD** | Global Reader role | Built-in (Microsoft Graph) |

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

**v2.0.2** - Documentation Update
- Added comprehensive BloodHound integration guide
- Added comprehensive PingCastle integration guide
- Added full assessment example with all data sources
- Added optional tool requirements table

**v2.0.1** - Bug Fixes
- Fixed Microsoft Graph connection issues
- Added device code authentication option (-UseDeviceCode)
- Better error messages and troubleshooting guidance
- Auto-install missing Graph sub-modules

**v2.0.0** - Windows 11 Optimized Package
- Flattened directory structure
- One-click setup installer
- Pure PowerShell runner (no WSL required)
