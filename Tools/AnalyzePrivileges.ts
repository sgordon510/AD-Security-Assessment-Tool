#!/usr/bin/env bun
// Active Directory Privilege Analysis Tool
// Identifies privilege escalation risks and overprivileged accounts

import { readFileSync } from 'fs';

interface Account {
  SamAccountName: string;
  DistinguishedName?: string;
  memberOf?: string[];
  lastLogon?: string;
  pwdLastSet?: string;
  AdminCount?: number;
  servicePrincipalNames?: string[];
  Enabled?: boolean;
  Description?: string;
}

interface Group {
  Name: string;
  members?: string[];
  Description?: string;
}

interface ACL {
  objectDN: string;
  trustee: string;
  rights: string[];
  isInherited: boolean;
}

interface IdentityData {
  collectionDate?: string;
  accounts: Account[];
  groups: Group[];
  acls?: ACL[];
}

interface PrivilegeFinding {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  category: string;
  title: string;
  description: string;
  impact: string;
  remediation: string;
  account?: string;
}

const PRIVILEGED_GROUPS = [
  'Domain Admins',
  'Enterprise Admins',
  'Schema Admins',
  'Administrators',
  'Account Operators',
  'Backup Operators',
  'Server Operators',
  'Print Operators',
  'DnsAdmins',
];

const DANGEROUS_RIGHTS = [
  'GenericAll',
  'GenericWrite',
  'WriteOwner',
  'WriteDacl',
  'AllExtendedRights',
  'ForceChangePassword',
  'AddMember',
];

function analyzePrivilegedAccounts(accounts: Account[]): PrivilegeFinding[] {
  const findings: PrivilegeFinding[] = [];

  const now = new Date();
  const ninetyDaysAgo = now.getTime() - (90 * 24 * 60 * 60 * 1000);
  const oneEightyDaysAgo = now.getTime() - (180 * 24 * 60 * 60 * 1000);

  const privilegedAccounts = accounts.filter(a =>
    a.AdminCount === 1 ||
    (a.memberOf && a.memberOf.some(g => PRIVILEGED_GROUPS.some(pg => g.includes(pg))))
  );

  // Check for dormant admin accounts
  const dormantAdmins = privilegedAccounts.filter(a => {
    if (!a.lastLogon || !a.Enabled) return false;
    const lastLogon = new Date(a.lastLogon).getTime();
    return lastLogon < ninetyDaysAgo;
  });

  if (dormantAdmins.length > 0) {
    findings.push({
      severity: 'HIGH',
      category: 'Dormant Accounts',
      title: `${dormantAdmins.length} Dormant Privileged Accounts`,
      description: `Privileged accounts with no activity in 90+ days: ${dormantAdmins.slice(0, 5).map(a => a.SamAccountName).join(', ')}${dormantAdmins.length > 5 ? '...' : ''}`,
      impact: 'Dormant privileged accounts are attractive targets for attackers and may indicate compromised or forgotten accounts',
      remediation: 'Review and disable unused privileged accounts. Implement privileged access lifecycle management',
      account: dormantAdmins.map(a => a.SamAccountName).join(', '),
    });
  }

  // Check for stale passwords on privileged accounts
  const stalePasswords = privilegedAccounts.filter(a => {
    if (!a.pwdLastSet || !a.Enabled) return false;
    const pwdLastSet = new Date(a.pwdLastSet).getTime();
    return pwdLastSet < oneEightyDaysAgo;
  });

  if (stalePasswords.length > 0) {
    findings.push({
      severity: 'HIGH',
      category: 'Password Hygiene',
      title: `${stalePasswords.length} Privileged Accounts with Stale Passwords`,
      description: `Privileged accounts with passwords older than 180 days: ${stalePasswords.slice(0, 5).map(a => a.SamAccountName).join(', ')}`,
      impact: 'Stale passwords increase risk of credential compromise through password spraying or previous breaches',
      remediation: 'Enforce regular password rotation for privileged accounts (90-180 day maximum)',
      account: stalePasswords.map(a => a.SamAccountName).join(', '),
    });
  }

  // Check for Kerberoastable accounts
  const kerberoastable = accounts.filter(a =>
    a.Enabled &&
    a.servicePrincipalNames &&
    a.servicePrincipalNames.length > 0
  );

  const kerberoastableAdmins = kerberoastable.filter(a =>
    a.AdminCount === 1 ||
    (a.memberOf && a.memberOf.some(g => PRIVILEGED_GROUPS.some(pg => g.includes(pg))))
  );

  if (kerberoastableAdmins.length > 0) {
    findings.push({
      severity: 'CRITICAL',
      category: 'Kerberoasting',
      title: `${kerberoastableAdmins.length} Kerberoastable Privileged Accounts`,
      description: `Privileged accounts with SPNs vulnerable to Kerberoasting: ${kerberoastableAdmins.map(a => a.SamAccountName).join(', ')}`,
      impact: 'Attackers can request service tickets and crack passwords offline, potentially gaining privileged access',
      remediation: 'Use Group Managed Service Accounts (gMSAs), remove unnecessary SPNs, or set 25+ character random passwords',
      account: kerberoastableAdmins.map(a => a.SamAccountName).join(', '),
    });
  }

  if (kerberoastable.length > kerberoastableAdmins.length) {
    findings.push({
      severity: 'MEDIUM',
      category: 'Kerberoasting',
      title: `${kerberoastable.length - kerberoastableAdmins.length} Standard Kerberoastable Accounts`,
      description: 'Non-privileged user accounts with Service Principal Names',
      impact: 'Can be targeted for offline password cracking attacks',
      remediation: 'Migrate service accounts to Group Managed Service Accounts (gMSAs)',
    });
  }

  return findings;
}

function analyzeGroupMembership(groups: Group[]): PrivilegeFinding[] {
  const findings: PrivilegeFinding[] = [];

  const privilegedGroups = groups.filter(g =>
    PRIVILEGED_GROUPS.some(pg => g.Name.includes(pg))
  );

  privilegedGroups.forEach(group => {
    if (group.members && group.members.length > 5) {
      findings.push({
        severity: 'MEDIUM',
        category: 'Group Membership',
        title: `Excessive Members in ${group.Name}`,
        description: `${group.Name} has ${group.members.length} members (recommended: minimize membership)`,
        impact: 'Large privileged groups increase attack surface and make access control harder to manage',
        remediation: 'Review membership and implement role-based access with smaller, focused groups',
      });
    }
  });

  // Check for service accounts in admin groups
  privilegedGroups.forEach(group => {
    if (group.members) {
      const serviceAccountMembers = group.members.filter(m =>
        m.toLowerCase().includes('svc') ||
        m.toLowerCase().includes('service')
      );

      if (serviceAccountMembers.length > 0) {
        findings.push({
          severity: 'HIGH',
          category: 'Service Account Privileges',
          title: `Service Accounts in ${group.Name}`,
          description: `Service accounts found in privileged group: ${serviceAccountMembers.slice(0, 3).join(', ')}`,
          impact: 'Service accounts in privileged groups create paths for privilege escalation',
          remediation: 'Remove service accounts from privileged groups. Grant only required permissions',
        });
      }
    }
  });

  return findings;
}

function analyzeACLs(acls: ACL[]): PrivilegeFinding[] {
  const findings: PrivilegeFinding[] = [];

  if (!acls || acls.length === 0) {
    return findings;
  }

  // Find dangerous non-inherited permissions
  const dangerousACLs = acls.filter(acl =>
    !acl.isInherited &&
    acl.rights.some(r => DANGEROUS_RIGHTS.some(dr => r.includes(dr)))
  );

  if (dangerousACLs.length > 0) {
    findings.push({
      severity: 'HIGH',
      category: 'Dangerous Permissions',
      title: `${dangerousACLs.length} Objects with Dangerous ACLs`,
      description: `Non-inherited dangerous permissions (GenericAll, WriteDacl, etc.) found on AD objects`,
      impact: 'These permissions can be exploited for privilege escalation and domain compromise',
      remediation: 'Audit and remove unnecessary permissions. Implement least privilege access controls',
    });
  }

  // Check for DCSync rights (Replicating Directory Changes)
  const dcSyncACLs = acls.filter(acl =>
    acl.rights.some(r =>
      r.includes('Replicating Directory Changes') ||
      r.includes('DS-Replication-Get-Changes')
    )
  );

  const nonDCTrustees = dcSyncACLs.filter(acl =>
    !acl.trustee.includes('Domain Controllers') &&
    !acl.trustee.includes('Enterprise Domain Controllers')
  );

  if (nonDCTrustees.length > 0) {
    findings.push({
      severity: 'CRITICAL',
      category: 'DCSync',
      title: 'Non-DC Accounts with DCSync Rights',
      description: `Accounts with replication rights that are not domain controllers: ${nonDCTrustees.map(a => a.trustee).join(', ')}`,
      impact: 'DCSync rights allow extraction of all password hashes from the domain, enabling full domain compromise',
      remediation: 'Remove DCSync rights from all non-DC accounts immediately',
    });
  }

  return findings;
}

function findPrivilegeEscalationPaths(accounts: Account[], acls: ACL[]): PrivilegeFinding[] {
  const findings: PrivilegeFinding[] = [];

  if (!acls || acls.length === 0) {
    return findings;
  }

  // Find non-privileged accounts with write access to privileged objects
  const privilegedDNs = accounts
    .filter(a => a.AdminCount === 1)
    .map(a => a.DistinguishedName)
    .filter(Boolean);

  const escalationPaths = acls.filter(acl => {
    const targetIsPrivileged = privilegedDNs.some(dn => acl.objectDN.includes(dn as string));
    const hasWriteAccess = acl.rights.some(r =>
      r.includes('GenericAll') ||
      r.includes('GenericWrite') ||
      r.includes('WriteOwner') ||
      r.includes('WriteDacl')
    );
    return targetIsPrivileged && hasWriteAccess && !acl.isInherited;
  });

  if (escalationPaths.length > 0) {
    findings.push({
      severity: 'CRITICAL',
      category: 'Privilege Escalation',
      title: `${escalationPaths.length} Privilege Escalation Paths Detected`,
      description: 'Non-privileged accounts have write access to privileged objects',
      impact: 'Attackers can chain these permissions to escalate to Domain Admin',
      remediation: 'Use BloodHound to map full attack paths. Remove unnecessary permissions from privileged objects',
    });
  }

  return findings;
}

function generateReport(findings: PrivilegeFinding[]): void {
  const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  console.log('\n═══════════════════════════════════════════════════════════');
  console.log('   AD SECURITY ASSESSMENT - PRIVILEGE ANALYSIS');
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

  findings.forEach(finding => {
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
    if (finding.account) {
      console.log(`   Affected Accounts: ${finding.account}`);
    }
    console.log('');
  });

  console.log('═══════════════════════════════════════════════════════════\n');
}

// Main execution
try {
  const inputFile = process.argv[2];

  if (!inputFile) {
    console.error('Usage: bun run AnalyzePrivileges.ts <identity-data.json>');
    console.error('\nExpected JSON structure:');
    console.error(JSON.stringify({
      accounts: [{
        SamAccountName: 'jdoe',
        memberOf: ['CN=Domain Admins,CN=Users,DC=example,DC=com'],
        lastLogon: '2025-12-15',
        pwdLastSet: '2025-06-01',
        AdminCount: 1,
        servicePrincipalNames: [],
        Enabled: true,
      }],
      groups: [{
        Name: 'Domain Admins',
        members: ['CN=jdoe,CN=Users,DC=example,DC=com'],
      }],
      acls: [{
        objectDN: 'CN=Domain Admins,CN=Users,DC=example,DC=com',
        trustee: 'EXAMPLE\\jdoe',
        rights: ['GenericAll'],
        isInherited: false,
      }],
    }, null, 2));
    process.exit(1);
  }

  const data: IdentityData = JSON.parse(readFileSync(inputFile, 'utf-8'));

  if (!data.accounts || data.accounts.length === 0) {
    console.error('Error: No accounts found in input data');
    process.exit(1);
  }

  const allFindings: PrivilegeFinding[] = [];

  allFindings.push(...analyzePrivilegedAccounts(data.accounts));
  allFindings.push(...analyzeGroupMembership(data.groups || []));

  if (data.acls) {
    allFindings.push(...analyzeACLs(data.acls));
    allFindings.push(...findPrivilegeEscalationPaths(data.accounts, data.acls));
  }

  generateReport(allFindings);

  const hasCritical = allFindings.some(f => f.severity === 'CRITICAL');
  process.exit(hasCritical ? 1 : 0);
} catch (error) {
  console.error('Error:', error);
  process.exit(1);
}
