# Azure Conditional Access Policy Analyzer

**Analyze your Azure/Entra ID Conditional Access policies for security gaps and misconfigurations.**

Identifies coverage gaps, baseline compliance issues, and policy misconfigurations. Generates executive-ready HTML reports with remediation guidance.

---

## Features

| Category | What We Check |
|----------|---------------|
| **Coverage Gaps** | Unprotected users, apps, admin roles, guest access |
| **MFA Enforcement** | MFA for all users, admins, Azure Management, risky sign-ins |
| **Legacy Auth** | Legacy authentication blocking (Exchange ActiveSync, etc.) |
| **Admin Protection** | Privileged role coverage, admin portal protection |
| **Risk Policies** | Sign-in risk, user risk, Identity Protection integration |
| **Device Controls** | Device compliance, Hybrid Azure AD join requirements |
| **Session Controls** | Sign-in frequency, persistent browser, CAE |
| **Best Practices** | Microsoft/CISA baseline alignment, emergency access |

### Security Checks (35+)

Inspired by [Maester](https://maester.dev) (MT.100x tests) and [CISA SCuBA](https://www.cisa.gov/resources-tools/services/secure-cloud-business-applications-scuba-project) baselines.

---

## Quick Start

### Option 1: Analyze from JSON File

```bash
# Export policies using Microsoft Graph PowerShell
Connect-MgGraph -Scopes "Policy.Read.All"
Get-MgIdentityConditionalAccessPolicy | ConvertTo-Json -Depth 10 > policies.json

# Run analysis
bun run src/index.ts -i policies.json -t "Your Organization"
```

### Option 2: Fetch Live from Azure

```bash
# Login to Azure CLI
az login

# Run analysis (fetches policies via Graph API)
bun run src/index.ts --live -t "Your Organization"
```

### Output

Reports are generated in `./reports/`:
- `ca-analysis-[timestamp].html` - Executive HTML dashboard
- `ca-analysis-[timestamp].json` - Machine-readable results
- `ca-analysis-[timestamp].md` - Markdown format

---

## Installation

### Prerequisites

- [Bun](https://bun.sh) runtime (v1.0+)
- Azure CLI (for `--live` mode) or exported policies JSON

### Install

```bash
git clone https://github.com/sgordon510/azure-ca-policy-analyzer.git
cd azure-ca-policy-analyzer
bun install
```

---

## Usage

```bash
# Basic analysis from file
bun run analyze -i policies.json

# Live fetch from Azure (requires az login)
bun run analyze:live -t "Contoso Inc"

# All output formats
bun run analyze -i policies.json -f all -o ./reports

# Show help
bun run analyze --help
```

### CLI Options

| Option | Description |
|--------|-------------|
| `-i, --input <file>` | Input JSON file with CA policies |
| `-o, --output <dir>` | Output directory (default: `./reports`) |
| `-f, --format <type>` | Output format: `html`, `json`, `markdown`, `all` |
| `-t, --tenant <name>` | Organization name for report header |
| `-l, --live` | Fetch policies live from Microsoft Graph |
| `--token <token>` | Access token (or uses Azure CLI) |
| `-h, --help` | Show help |

---

## Input Format

### Option A: Direct Policy Array
```json
[
  { "id": "...", "displayName": "Policy 1", ... },
  { "id": "...", "displayName": "Policy 2", ... }
]
```

### Option B: Structured Input
```json
{
  "policies": [...],
  "namedLocations": [...],
  "emergencyAccounts": ["account-id-1", "group-id-1"]
}
```

### Exporting from Azure

**Microsoft Graph PowerShell:**
```powershell
Connect-MgGraph -Scopes "Policy.Read.All", "Policy.ReadWrite.ConditionalAccess"

# Export policies
Get-MgIdentityConditionalAccessPolicy | ConvertTo-Json -Depth 10 > policies.json

# Export named locations
Get-MgIdentityConditionalAccessNamedLocation | ConvertTo-Json -Depth 10 > locations.json
```

**Azure CLI:**
```bash
az rest --method GET --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" > policies.json
```

---

## Sample Output

```
🔍 Azure Conditional Access Policy Analyzer

Loading policies from policies.json...
  Loaded 7 policies

Running security analysis...

═══════════════════════════════════════════════════════════════
                    ANALYSIS SUMMARY
═══════════════════════════════════════════════════════════════

  Security Score: 72/100
  Total Policies: 7
    - Enabled: 5
    - Report-Only: 1
    - Disabled: 1

  Findings: 8
    🔴 Critical: 0
    🟠 High:     2
    🟡 Medium:   4
    🔵 Low:      2
    ⚪ Info:     0

  Security Coverage:
    ✅ MFA Enforcement
    ✅ Legacy Auth Blocked
    ✅ Admin MFA Required
    ❌ Risk Policies
    ❌ Device Compliance
    ✅ Guest Access Controlled

═══════════════════════════════════════════════════════════════

📄 Generated: ./reports/ca-analysis-2026-01-21T12-30-00.html

Analysis complete.
```

---

## Security Checks Reference

### Baseline Checks (MT.100x)

| ID | Check | Severity |
|----|-------|----------|
| MT.1001 | Device compliance policy exists | MEDIUM |
| MT.1003 | All cloud apps policy exists | HIGH |
| MT.1005 | Emergency access exclusions | HIGH |
| MT.1006 | MFA for admin roles | CRITICAL |
| MT.1007 | MFA for all users | HIGH |
| MT.1008 | MFA for Azure Management | HIGH |
| MT.1010 | Block legacy authentication | HIGH |
| MT.1012 | MFA for risky sign-ins | MEDIUM |
| MT.1013 | Password change for high-risk users | MEDIUM |

### Misconfiguration Checks

- Report-only policies > 30 days old
- Policies with overly broad exclusions
- Privileged roles excluded from MFA
- MFA bypassable via OR operator
- No location-based controls for admins

### Gap Analysis

- Permutation-based coverage testing
- Admin access without MFA
- Legacy auth not fully blocked
- Azure Management unprotected
- Guest users without MFA

---

## Project Structure

```
azure-ca-policy-analyzer/
├── src/
│   ├── index.ts                 # CLI entry point
│   ├── types.ts                 # TypeScript definitions
│   ├── graph/
│   │   └── client.ts            # Microsoft Graph API client
│   ├── analyzers/
│   │   ├── gapAnalyzer.ts       # Coverage gap detection
│   │   ├── misconfigAnalyzer.ts # Misconfiguration detection
│   │   └── baselineAnalyzer.ts  # Best practice checks
│   └── report/
│       └── htmlReport.ts        # Report generators
├── sample-data/
│   └── sample-policies.json     # Example input
├── package.json
└── README.md
```

---

## References

- [Microsoft CA Best Practices](https://learn.microsoft.com/en-us/entra/identity/conditional-access/plan-conditional-access)
- [CISA SCuBA Project](https://www.cisa.gov/resources-tools/services/secure-cloud-business-applications-scuba-project)
- [Maester Security Tests](https://maester.dev/docs/tests/maester/)
- [CA Optics Gap Analyzer](https://github.com/jsa2/caOptics)

---

## License

MIT
