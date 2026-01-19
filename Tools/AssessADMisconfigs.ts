#!/usr/bin/env bun
// AD Misconfiguration Assessment Tool
// Detects security weaknesses in Active Directory configurations

import { readFileSync } from 'fs';

interface ADConfig {
  domain?: string;
  passwordPolicy?: {
    minimumPasswordLength?: number;
    passwordComplexity?: boolean;
    lockoutThreshold?: number;
    maximumPasswordAge?: number;
  };
  gpos?: Array<{
    name: string;
    settings: Record<string, any>;
  }>;
  domainControllers?: Array<{
    hostname: string;
    osVersion?: string;
    lastPatchDate?: string;
  }>;
  ldapSettings?: {
    ldapSigning?: boolean;
    channelBinding?: boolean;
    ssl?: boolean;
  };
  serviceAccounts?: Array<{
    name: string;
    passwordLastSet?: string;
    kerberosPreAuthRequired?: boolean;
  }>;
}

interface Finding {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  category: string;
  title: string;
  description: string;
  remediation: string;
  cve?: string;
  references?: string[];
}

function assessPasswordPolicy(policy: ADConfig['passwordPolicy']): Finding[] {
  const findings: Finding[] = [];

  if (!policy) {
    findings.push({
      severity: 'HIGH',
      category: 'Password Policy',
      title: 'No Password Policy Configured',
      description: 'Domain has no password policy configured',
      remediation: 'Implement a strong password policy with minimum length 14+, complexity enabled',
    });
    return findings;
  }

  if (policy.minimumPasswordLength && policy.minimumPasswordLength < 12) {
    findings.push({
      severity: 'HIGH',
      category: 'Password Policy',
      title: 'Weak Minimum Password Length',
      description: `Minimum password length is ${policy.minimumPasswordLength} characters (recommended: 14+)`,
      remediation: 'Increase minimum password length to at least 14 characters',
      references: ['NIST SP 800-63B', 'CIS Benchmark for Active Directory'],
    });
  }

  if (!policy.passwordComplexity) {
    findings.push({
      severity: 'MEDIUM',
      category: 'Password Policy',
      title: 'Password Complexity Not Enforced',
      description: 'Password complexity requirements are not enabled',
      remediation: 'Enable password complexity requirements',
    });
  }

  if (!policy.lockoutThreshold || policy.lockoutThreshold === 0) {
    findings.push({
      severity: 'MEDIUM',
      category: 'Password Policy',
      title: 'No Account Lockout Policy',
      description: 'Account lockout is not configured, allowing unlimited password guessing attempts',
      remediation: 'Configure account lockout threshold (recommended: 5-10 invalid attempts)',
    });
  }

  if (policy.maximumPasswordAge && policy.maximumPasswordAge > 90) {
    findings.push({
      severity: 'LOW',
      category: 'Password Policy',
      title: 'Long Maximum Password Age',
      description: `Passwords expire after ${policy.maximumPasswordAge} days (recommended: 60-90 days)`,
      remediation: 'Reduce maximum password age to 60-90 days',
    });
  }

  return findings;
}

function assessLDAPSecurity(ldap: ADConfig['ldapSettings']): Finding[] {
  const findings: Finding[] = [];

  if (!ldap) {
    findings.push({
      severity: 'HIGH',
      category: 'LDAP Security',
      title: 'LDAP Security Settings Unknown',
      description: 'Unable to determine LDAP security configuration',
      remediation: 'Review and harden LDAP settings',
    });
    return findings;
  }

  if (!ldap.ldapSigning) {
    findings.push({
      severity: 'CRITICAL',
      category: 'LDAP Security',
      title: 'LDAP Signing Not Enforced',
      description: 'LDAP signing is not required, allowing man-in-the-middle attacks',
      remediation: 'Enable LDAP signing requirement on all domain controllers',
      references: ['MS CVE-2020-1041', 'AD FS Exploit Chain'],
    });
  }

  if (!ldap.channelBinding) {
    findings.push({
      severity: 'HIGH',
      category: 'LDAP Security',
      title: 'LDAP Channel Binding Not Enforced',
      description: 'LDAP channel binding is not required, increasing relay attack risk',
      remediation: 'Enable LDAP channel binding to prevent relay attacks',
    });
  }

  if (!ldap.ssl) {
    findings.push({
      severity: 'HIGH',
      category: 'LDAP Security',
      title: 'LDAPS Not Enforced',
      description: 'LDAP over SSL/TLS is not enforced, allowing credential exposure',
      remediation: 'Require LDAPS for all LDAP communications',
    });
  }

  return findings;
}

function assessDomainControllers(dcs: ADConfig['domainControllers']): Finding[] {
  const findings: Finding[] = [];

  if (!dcs || dcs.length === 0) {
    findings.push({
      severity: 'INFO',
      category: 'Domain Controllers',
      title: 'No Domain Controller Data',
      description: 'No domain controller information provided',
      remediation: 'Provide domain controller details for assessment',
    });
    return findings;
  }

  dcs.forEach((dc) => {
    // Check for outdated OS versions
    if (dc.osVersion && (dc.osVersion.includes('2008') || dc.osVersion.includes('2012'))) {
      findings.push({
        severity: 'CRITICAL',
        category: 'Domain Controllers',
        title: `Unsupported Domain Controller OS: ${dc.hostname}`,
        description: `${dc.hostname} is running ${dc.osVersion} which is end-of-life`,
        remediation: 'Upgrade domain controllers to a supported Windows Server version',
      });
    }

    // Check patch date
    if (dc.lastPatchDate) {
      const patchDate = new Date(dc.lastPatchDate);
      const now = new Date();
      const daysSincePatched = Math.floor((now.getTime() - patchDate.getTime()) / (1000 * 60 * 60 * 24));

      if (daysSincePatched > 90) {
        findings.push({
          severity: 'HIGH',
          category: 'Domain Controllers',
          title: `Unpatched Domain Controller: ${dc.hostname}`,
          description: `${dc.hostname} has not been patched in ${daysSincePatched} days`,
          remediation: 'Apply latest security patches to domain controllers',
        });
      }
    }
  });

  return findings;
}

function assessServiceAccounts(accounts: ADConfig['serviceAccounts']): Finding[] {
  const findings: Finding[] = [];

  if (!accounts || accounts.length === 0) {
    return findings;
  }

  accounts.forEach((account) => {
    if (!account.kerberosPreAuthRequired) {
      findings.push({
        severity: 'CRITICAL',
        category: 'Service Accounts',
        title: `Kerberos Pre-Auth Disabled: ${account.name}`,
        description: `Account ${account.name} does not require Kerberos pre-authentication (AS-REP Roasting vulnerability)`,
        remediation: 'Enable Kerberos pre-authentication requirement',
        references: ['AS-REP Roasting Attack'],
      });
    }

    if (account.passwordLastSet) {
      const passwordDate = new Date(account.passwordLastSet);
      const now = new Date();
      const daysSinceChanged = Math.floor((now.getTime() - passwordDate.getTime()) / (1000 * 60 * 60 * 24));

      if (daysSinceChanged > 365) {
        findings.push({
          severity: 'HIGH',
          category: 'Service Accounts',
          title: `Stale Service Account Password: ${account.name}`,
          description: `Service account ${account.name} password has not been changed in ${daysSinceChanged} days`,
          remediation: 'Rotate service account passwords regularly (recommended: every 90-180 days)',
        });
      }
    }
  });

  return findings;
}

function generateReport(findings: Finding[]): void {
  // Sort by severity
  const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  console.log('\n═══════════════════════════════════════════════════════════');
  console.log('   AD SECURITY ASSESSMENT - MISCONFIGURATION ANALYSIS');
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

  findings.forEach((finding, index) => {
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
    console.error('Usage: bun run AssessADMisconfigs.ts <ad-config.json>');
    console.error('\nExample input JSON structure:');
    console.error(JSON.stringify({
      domain: 'example.com',
      passwordPolicy: {
        minimumPasswordLength: 8,
        passwordComplexity: true,
        lockoutThreshold: 5,
        maximumPasswordAge: 90,
      },
      ldapSettings: {
        ldapSigning: false,
        channelBinding: false,
        ssl: true,
      },
      domainControllers: [
        {
          hostname: 'DC01',
          osVersion: 'Windows Server 2019',
          lastPatchDate: '2025-12-01',
        },
      ],
      serviceAccounts: [
        {
          name: 'svc_backup',
          passwordLastSet: '2024-01-01',
          kerberosPreAuthRequired: true,
        },
      ],
    }, null, 2));
    process.exit(1);
  }

  const data: ADConfig = JSON.parse(readFileSync(inputFile, 'utf-8'));

  const allFindings: Finding[] = [];

  // Run all assessments
  allFindings.push(...assessPasswordPolicy(data.passwordPolicy));
  allFindings.push(...assessLDAPSecurity(data.ldapSettings));
  allFindings.push(...assessDomainControllers(data.domainControllers));
  allFindings.push(...assessServiceAccounts(data.serviceAccounts));

  // Generate report
  generateReport(allFindings);

  // Exit with appropriate code
  const hasCritical = allFindings.some((f) => f.severity === 'CRITICAL');
  process.exit(hasCritical ? 1 : 0);
} catch (error) {
  console.error('Error:', error);
  process.exit(1);
}
