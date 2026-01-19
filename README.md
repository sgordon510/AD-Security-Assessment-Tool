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

## Version

**v2.0.0** - Windows 11 Optimized Package
- Flattened directory structure
- One-click setup installer
- Pure PowerShell runner (no WSL required)
