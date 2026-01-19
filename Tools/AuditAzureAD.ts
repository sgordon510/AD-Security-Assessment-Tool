#!/usr/bin/env bun
// Azure AD Security Posture Assessment Tool
// Evaluates Azure AD security configuration and identifies risks

import { readFileSync } from 'fs';

interface AzureADUser {
  userPrincipalName: string;
  displayName: string;
  userType?: 'Member' | 'Guest';
  accountEnabled?: boolean;
  mfaStatus?: 'enabled' | 'enforced' | 'disabled';
  lastSignIn?: string;
  createdDateTime?: string;
  assignedRoles?: string[];
  riskLevel?: 'none' | 'low' | 'medium' | 'high';
}

interface ConditionalAccessPolicy {
  name: string;
  state: 'enabled' | 'disabled' | 'enabledForReportingButNotEnforced';
  conditions?: {
    users?: { includeUsers?: string[]; excludeUsers?: string[] };
    applications?: { includeApplications?: string[] };
    platforms?: string[];
    locations?: string[];
    signInRiskLevels?: string[];
  };
  grantControls?: {
    builtInControls?: string[];
  };
}

interface PIMConfiguration {
  roleName: string;
  eligibleAssignments?: number;
  activeAssignments?: number;
  maxActivationDuration?: number;
  requireJustification?: boolean;
  requireMFA?: boolean;
  requireApproval?: boolean;
}

interface AzureADConfig {
  users: AzureADUser[];
  conditionalAccessPolicies?: ConditionalAccessPolicy[];
  pimConfiguration?: PIMConfiguration[];
  legacyAuthEnabled?: boolean;
  securityDefaults?: boolean;
  passwordProtection?: {
    customBannedPasswords?: string[];
    enabledOnPremises?: boolean;
  };
}

interface AzureFinding {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  category: string;
  title: string;
  description: string;
  impact: string;
  remediation: string;
  references?: string[];
}

function assessMFACompliance(users: AzureADUser[]): AzureFinding[] {
  const findings: AzureFinding[] = [];

  const totalUsers = users.filter((u) => u.userType === 'Member' && u.accountEnabled).length;
  const usersWithoutMFA = users.filter(
    (u) => u.userType === 'Member' && u.accountEnabled && (!u.mfaStatus || u.mfaStatus === 'disabled')
  );

  const mfaComplianceRate = ((totalUsers - usersWithoutMFA.length) / totalUsers) * 100;

  if (mfaComplianceRate < 100) {
    const severity = mfaComplianceRate < 50 ? 'CRITICAL' : mfaComplianceRate < 80 ? 'HIGH' : 'MEDIUM';

    findings.push({
      severity,
      category: 'MFA Compliance',
      title: `Low MFA Adoption Rate: ${mfaComplianceRate.toFixed(1)}%`,
      description: `${usersWithoutMFA.length} of ${totalUsers} enabled users do not have MFA enabled`,
      impact: 'Users without MFA are vulnerable to password-based attacks and account takeover',
      remediation: 'Enforce MFA for all users through Conditional Access policies or Security Defaults',
      references: ['Microsoft Zero Trust', 'Azure AD Security Best Practices'],
    });

    // List specific high-risk users without MFA
    const privilegedWithoutMFA = usersWithoutMFA.filter(
      (u) => u.assignedRoles && u.assignedRoles.length > 0
    );

    if (privilegedWithoutMFA.length > 0) {
      findings.push({
        severity: 'CRITICAL',
        category: 'Privileged User Without MFA',
        title: 'Privileged Accounts Without MFA Protection',
        description: `${privilegedWithoutMFA.length} privileged accounts do not have MFA enabled: ${privilegedWithoutMFA.map((u) => u.userPrincipalName).slice(0, 5).join(', ')}${privilegedWithoutMFA.length > 5 ? '...' : ''}`,
        impact: 'Privileged accounts without MFA are prime targets for attackers and can lead to full tenant compromise',
        remediation: 'Immediately enforce MFA for all privileged accounts through Conditional Access',
      });
    }
  }

  return findings;
}

function assessConditionalAccess(policies: ConditionalAccessPolicy[]): AzureFinding[] {
  const findings: AzureFinding[] = [];

  if (!policies || policies.length === 0) {
    findings.push({
      severity: 'CRITICAL',
      category: 'Conditional Access',
      title: 'No Conditional Access Policies Configured',
      description: 'Tenant has no Conditional Access policies, missing critical security controls',
      impact: 'No dynamic access controls based on risk, location, device compliance, or other signals',
      remediation: 'Implement Conditional Access policies for MFA enforcement, device compliance, and risk-based access',
      references: ['Azure AD Conditional Access Best Practices'],
    });
    return findings;
  }

  const enabledPolicies = policies.filter((p) => p.state === 'enabled');
  const reportOnlyPolicies = policies.filter(
    (p) => p.state === 'enabledForReportingButNotEnforced'
  );

  if (reportOnlyPolicies.length > 0) {
    findings.push({
      severity: 'MEDIUM',
      category: 'Conditional Access',
      title: `${reportOnlyPolicies.length} Conditional Access Policies in Report-Only Mode`,
      description: `Policies not enforced: ${reportOnlyPolicies.map((p) => p.name).join(', ')}`,
      impact: 'Security controls are not being enforced, only monitored',
      remediation: 'Review report-only policies and enable enforcement once validated',
    });
  }

  // Check for MFA enforcement
  const mfaPolicies = enabledPolicies.filter((p) =>
    p.grantControls?.builtInControls?.includes('mfa')
  );

  if (mfaPolicies.length === 0) {
    findings.push({
      severity: 'CRITICAL',
      category: 'Conditional Access',
      title: 'No MFA Enforcement via Conditional Access',
      description: 'No enabled Conditional Access policies require multi-factor authentication',
      impact: 'Users may not be required to use MFA, leaving accounts vulnerable',
      remediation: 'Create Conditional Access policy to require MFA for all users',
    });
  }

  // Check for sign-in risk policies
  const riskBasedPolicies = enabledPolicies.filter(
    (p) => p.conditions?.signInRiskLevels && p.conditions.signInRiskLevels.length > 0
  );

  if (riskBasedPolicies.length === 0) {
    findings.push({
      severity: 'MEDIUM',
      category: 'Conditional Access',
      title: 'No Risk-Based Conditional Access Policies',
      description: 'No policies leverage Azure AD Identity Protection risk signals',
      impact: 'Missing automated risk-based access controls',
      remediation: 'Implement risk-based Conditional Access policies using Identity Protection',
      references: ['Azure AD Identity Protection'],
    });
  }

  return findings;
}

function assessPIM(pimConfig: PIMConfiguration[]): AzureFinding[] {
  const findings: AzureFinding[] = [];

  if (!pimConfig || pimConfig.length === 0) {
    findings.push({
      severity: 'HIGH',
      category: 'Privileged Identity Management',
      title: 'PIM Not Configured',
      description: 'Privileged Identity Management (PIM) is not configured for any roles',
      impact: 'Standing privileged access increases risk of credential theft and insider threats',
      remediation: 'Configure PIM for all privileged roles (Global Admin, Security Admin, etc.)',
      references: ['Azure AD PIM Best Practices'],
    });
    return findings;
  }

  pimConfig.forEach((role) => {
    // Check for permanent assignments
    if (role.activeAssignments && role.activeAssignments > 0) {
      findings.push({
        severity: 'HIGH',
        category: 'PIM',
        title: `Permanent Role Assignments: ${role.roleName}`,
        description: `${role.activeAssignments} permanent active assignments for ${role.roleName}`,
        impact: 'Permanent privileged access increases attack surface and insider threat risk',
        remediation: 'Convert permanent assignments to eligible (time-bound) assignments',
      });
    }

    // Check activation requirements
    if (!role.requireMFA) {
      findings.push({
        severity: 'HIGH',
        category: 'PIM',
        title: `MFA Not Required for Role Activation: ${role.roleName}`,
        description: `Role ${role.roleName} does not require MFA for activation`,
        impact: 'Attackers with stolen credentials can activate privileged roles without additional verification',
        remediation: 'Require MFA for all privileged role activations',
      });
    }

    if (!role.requireJustification) {
      findings.push({
        severity: 'MEDIUM',
        category: 'PIM',
        title: `Justification Not Required: ${role.roleName}`,
        description: `Role ${role.roleName} activation does not require justification`,
        impact: 'Lack of audit trail for why privileged access was activated',
        remediation: 'Require justification for all role activations',
      });
    }

    // Check activation duration
    if (role.maxActivationDuration && role.maxActivationDuration > 8) {
      findings.push({
        severity: 'MEDIUM',
        category: 'PIM',
        title: `Long Activation Duration: ${role.roleName}`,
        description: `Maximum activation duration is ${role.maxActivationDuration} hours (recommended: ≤8 hours)`,
        impact: 'Longer activation periods increase the window for potential compromise',
        remediation: 'Reduce maximum activation duration to 8 hours or less',
      });
    }
  });

  return findings;
}

function assessGuestUsers(users: AzureADUser[]): AzureFinding[] {
  const findings: AzureFinding[] = [];

  const guestUsers = users.filter((u) => u.userType === 'Guest');
  const staleGuests = guestUsers.filter((u) => {
    if (!u.lastSignIn) return true;
    const daysSinceSignIn = Math.floor(
      (Date.now() - new Date(u.lastSignIn).getTime()) / (1000 * 60 * 60 * 24)
    );
    return daysSinceSignIn > 90;
  });

  if (guestUsers.length > 0) {
    findings.push({
      severity: 'INFO',
      category: 'Guest Users',
      title: `${guestUsers.length} Guest Users in Tenant`,
      description: `Tenant has ${guestUsers.length} guest user accounts`,
      impact: 'Guest users increase attack surface and require monitoring',
      remediation: 'Regularly review guest access and remove accounts that are no longer needed',
    });
  }

  if (staleGuests.length > 0) {
    findings.push({
      severity: 'MEDIUM',
      category: 'Guest Users',
      title: `${staleGuests.length} Stale Guest Accounts`,
      description: `Guest accounts with no sign-in activity in 90+ days`,
      impact: 'Dormant guest accounts may represent former partners/contractors with lingering access',
      remediation: 'Review and remove guest accounts with no recent activity. Implement access reviews',
    });
  }

  return findings;
}

function assessSecurityBaseline(config: AzureADConfig): AzureFinding[] {
  const findings: AzureFinding[] = [];

  // Check for legacy authentication
  if (config.legacyAuthEnabled) {
    findings.push({
      severity: 'HIGH',
      category: 'Legacy Authentication',
      title: 'Legacy Authentication Protocols Enabled',
      description: 'Tenant allows legacy authentication protocols (e.g., Basic Auth, POP3, IMAP)',
      impact: 'Legacy auth bypasses MFA and modern security controls, enabling credential spray attacks',
      remediation: 'Disable legacy authentication through Conditional Access policies',
      references: ['Block legacy authentication in Azure AD'],
    });
  }

  // Check for security defaults
  if (config.securityDefaults === false && (!config.conditionalAccessPolicies || config.conditionalAccessPolicies.length === 0)) {
    findings.push({
      severity: 'CRITICAL',
      category: 'Security Baseline',
      title: 'Security Defaults Disabled Without Conditional Access',
      description: 'Security Defaults are disabled but no Conditional Access policies are configured',
      impact: 'Tenant lacks baseline security protections (MFA, block legacy auth, etc.)',
      remediation: 'Enable Security Defaults or implement equivalent Conditional Access policies',
    });
  }

  // Check password protection
  if (!config.passwordProtection?.customBannedPasswords || config.passwordProtection.customBannedPasswords.length === 0) {
    findings.push({
      severity: 'LOW',
      category: 'Password Protection',
      title: 'No Custom Banned Passwords',
      description: 'No custom banned password list configured',
      impact: 'Users may choose passwords specific to your organization (company name, products, etc.)',
      remediation: 'Configure custom banned passwords in Azure AD Password Protection',
    });
  }

  return findings;
}

function generateReport(findings: AzureFinding[]): void {
  // Sort by severity
  const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  console.log('\n═══════════════════════════════════════════════════════════');
  console.log('   AZURE AD SECURITY ASSESSMENT');
  console.log('═══════════════════════════════════════════════════════════\n');

  const summary = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  console.log('SUMMARY:');
  console.log(`  🔴 CRITICAL: ${summary.CRITICAL || 0}`);
  console.log(`  🟠 HIGH:     ${summary.HIGH || 0}`);
  console.log(`  🟡 MEDIUM:   ${summary.MEDIUM || 0}`);
  console.log(`  🔵 LOW:      ${summary.LOW || 0}`);
  console.log(`  ⚪ INFO:     ${summary.INFO || 0}`);
  console.log(`\n  Total Findings: ${findings.length}\n`);

  console.log('═══════════════════════════════════════════════════════════\n');

  findings.forEach((finding) => {
    const icon = {
      CRITICAL: '🔴',
      HIGH: '🟠',
      MEDIUM: '🟡',
      LOW: '🔵',
      INFO: '⚪',
    }[finding.severity];

    console.log(`${icon} [${finding.severity}] ${finding.title}`);
    console.log(`   Category: ${finding.category}`);
    console.log(`   ${finding.description}`);
    console.log(`   Impact: ${finding.impact}`);
    console.log(`   Remediation: ${finding.remediation}`);
    if (finding.references) {
      console.log(`   References: ${finding.references.join(', ')}`);
    }
    console.log('');
  });

  console.log('═══════════════════════════════════════════════════════════\n');
}

// Main execution
try {
  const inputFile = process.argv[2];

  if (!inputFile) {
    console.error('Usage: bun run AuditAzureAD.ts <azure-ad-data.json>');
    console.error('\nExample input JSON structure:');
    console.error(JSON.stringify({
      users: [
        {
          userPrincipalName: 'jdoe@example.com',
          displayName: 'John Doe',
          userType: 'Member',
          accountEnabled: true,
          mfaStatus: 'enabled',
          lastSignIn: '2026-01-15T00:00:00Z',
          assignedRoles: ['Global Administrator'],
        },
      ],
      conditionalAccessPolicies: [
        {
          name: 'Require MFA for All Users',
          state: 'enabled',
          grantControls: { builtInControls: ['mfa'] },
        },
      ],
      legacyAuthEnabled: false,
      securityDefaults: true,
    }, null, 2));
    process.exit(1);
  }

  const data: AzureADConfig = JSON.parse(readFileSync(inputFile, 'utf-8'));

  if (!data.users || data.users.length === 0) {
    console.error('Error: No users found in input data');
    process.exit(1);
  }

  const allFindings: AzureFinding[] = [];

  // Run all assessments
  allFindings.push(...assessMFACompliance(data.users));
  allFindings.push(...assessGuestUsers(data.users));
  allFindings.push(...assessSecurityBaseline(data));

  if (data.conditionalAccessPolicies) {
    allFindings.push(...assessConditionalAccess(data.conditionalAccessPolicies));
  }

  if (data.pimConfiguration) {
    allFindings.push(...assessPIM(data.pimConfiguration));
  }

  // Generate report
  generateReport(allFindings);

  // Exit with appropriate code
  const hasCritical = allFindings.some((f) => f.severity === 'CRITICAL');
  process.exit(hasCritical ? 1 : 0);
} catch (error) {
  console.error('Error:', error);
  process.exit(1);
}
