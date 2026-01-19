#!/usr/bin/env bun
// BloodHound Data Parser
// Extracts security findings from BloodHound JSON output

import { readFileSync, existsSync, readdirSync } from 'fs';
import { join } from 'path';

interface Finding {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  category: string;
  title: string;
  description: string;
  remediation: string;
  impact: string;
  account?: string;
}

interface BloodHoundUser {
  Properties: {
    name: string;
    enabled?: boolean;
    lastlogon?: number;
    pwdlastset?: number;
    hasspn?: boolean;
    dontreqpreauth?: boolean;
    admincount?: boolean;
    highvalue?: boolean;
    description?: string;
  };
  Aces?: Array<{
    PrincipalName: string;
    PrincipalType: string;
    RightName: string;
    AceType: string;
    IsInherited: boolean;
  }>;
}

interface BloodHoundComputer {
  Properties: {
    name: string;
    enabled?: boolean;
    operatingsystem?: string;
    unconstraineddelegation?: boolean;
    haslaps?: boolean;
    highvalue?: boolean;
  };
}

interface BloodHoundGroup {
  Properties: {
    name: string;
    highvalue?: boolean;
    admincount?: boolean;
  };
  Members?: Array<{
    MemberName: string;
    MemberType: string;
  }>;
}

interface BloodHoundData {
  users?: { users: BloodHoundUser[] };
  computers?: { computers: BloodHoundComputer[] };
  groups?: { groups: BloodHoundGroup[] };
}

function analyzeKerberoastableAccounts(users: BloodHoundUser[]): Finding[] {
  const findings: Finding[] = [];

  const kerberoastable = users.filter(u => u.Properties.hasspn && u.Properties.enabled);

  if (kerberoastable.length > 0) {
    // Check for high-value kerberoastable accounts
    const highValueKerberoastable = kerberoastable.filter(u =>
      u.Properties.highvalue || u.Properties.admincount
    );

    if (highValueKerberoastable.length > 0) {
      findings.push({
        severity: 'CRITICAL',
        category: 'Kerberoasting',
        title: `${highValueKerberoastable.length} High-Value Kerberoastable Accounts`,
        description: `Privileged accounts with SPNs can be targeted for offline password cracking: ${highValueKerberoastable.slice(0, 5).map(u => u.Properties.name).join(', ')}${highValueKerberoastable.length > 5 ? '...' : ''}`,
        impact: 'Attackers can request service tickets and crack passwords offline. Compromise of these accounts leads to privileged access.',
        remediation: 'Use Group Managed Service Accounts (gMSAs) or set passwords to 25+ random characters. Remove SPNs from high-privilege accounts.',
        account: highValueKerberoastable.map(u => u.Properties.name).join(', '),
      });
    }

    if (kerberoastable.length > highValueKerberoastable.length) {
      findings.push({
        severity: 'MEDIUM',
        category: 'Kerberoasting',
        title: `${kerberoastable.length - highValueKerberoastable.length} Standard Kerberoastable Accounts`,
        description: `User accounts with Service Principal Names (SPNs) are vulnerable to Kerberoasting attacks`,
        impact: 'Attackers can perform offline password cracking. Risk increases with weak passwords.',
        remediation: 'Migrate to Group Managed Service Accounts (gMSAs) or enforce strong passwords (25+ characters).',
      });
    }
  }

  return findings;
}

function analyzeASREPRoastable(users: BloodHoundUser[]): Finding[] {
  const findings: Finding[] = [];

  const asrepRoastable = users.filter(u => u.Properties.dontreqpreauth && u.Properties.enabled);

  if (asrepRoastable.length > 0) {
    findings.push({
      severity: 'CRITICAL',
      category: 'AS-REP Roasting',
      title: `${asrepRoastable.length} AS-REP Roastable Accounts`,
      description: `Accounts do not require Kerberos pre-authentication: ${asrepRoastable.slice(0, 5).map(u => u.Properties.name).join(', ')}${asrepRoastable.length > 5 ? '...' : ''}`,
      impact: 'Attackers can request authentication tickets and crack passwords offline without needing current credentials.',
      remediation: 'Enable "Kerberos pre-authentication required" for all accounts. This is rarely needed and usually indicates misconfiguration.',
      account: asrepRoastable.map(u => u.Properties.name).join(', '),
    });
  }

  return findings;
}

function analyzeUnconstrainedDelegation(computers: BloodHoundComputer[]): Finding[] {
  const findings: Finding[] = [];

  const unconstrainedDelegation = computers.filter(c =>
    c.Properties.unconstraineddelegation &&
    c.Properties.enabled &&
    !c.Properties.name.toLowerCase().includes('dc')  // Exclude DCs (expected)
  );

  if (unconstrainedDelegation.length > 0) {
    findings.push({
      severity: 'HIGH',
      category: 'Unconstrained Delegation',
      title: `${unconstrainedDelegation.length} Computers with Unconstrained Delegation`,
      description: `Non-DC computers configured for unconstrained Kerberos delegation: ${unconstrainedDelegation.slice(0, 5).map(c => c.Properties.name).join(', ')}`,
      impact: 'Can be exploited to impersonate any user (including Domain Admins) who authenticates to these systems. High risk for privilege escalation.',
      remediation: 'Migrate to constrained delegation or resource-based constrained delegation. Remove unconstrained delegation from non-DC systems.',
    });
  }

  return findings;
}

function analyzeLAPSCoverage(computers: BloodHoundComputer[]): Finding[] {
  const findings: Finding[] = [];

  const enabledComputers = computers.filter(c => c.Properties.enabled);
  const withoutLAPS = enabledComputers.filter(c => !c.Properties.haslaps);

  if (withoutLAPS.length > 0 && enabledComputers.length > 0) {
    const percentWithoutLAPS = (withoutLAPS.length / enabledComputers.length) * 100;

    if (percentWithoutLAPS > 50) {
      findings.push({
        severity: 'HIGH',
        category: 'LAPS Coverage',
        title: `Low LAPS Deployment: ${percentWithoutLAPS.toFixed(0)}% of computers lack LAPS`,
        description: `${withoutLAPS.length} of ${enabledComputers.length} enabled computers do not have Local Administrator Password Solution (LAPS) configured`,
        impact: 'Without LAPS, local administrator passwords may be shared or weak, enabling lateral movement via password reuse.',
        remediation: 'Deploy LAPS to all workstations and servers. Configure automatic password rotation.',
      });
    } else if (percentWithoutLAPS > 0) {
      findings.push({
        severity: 'MEDIUM',
        category: 'LAPS Coverage',
        title: `${withoutLAPS.length} Computers Without LAPS`,
        description: `${percentWithoutLAPS.toFixed(0)}% of computers do not have LAPS configured`,
        impact: 'Gaps in LAPS coverage create opportunities for lateral movement.',
        remediation: 'Complete LAPS deployment to remaining computers.',
      });
    }
  }

  return findings;
}

function analyzeDangerousPermissions(users: BloodHoundUser[]): Finding[] {
  const findings: Finding[] = [];

  const dangerousRights = [
    'GenericAll',
    'GenericWrite',
    'WriteOwner',
    'WriteDacl',
    'AllExtendedRights',
    'ForceChangePassword',
    'AddMember',
  ];

  let usersWithDangerousPerms = 0;
  const examples: string[] = [];

  users.forEach(user => {
    if (user.Aces) {
      const hasDangerousPerms = user.Aces.some(ace =>
        dangerousRights.some(right => ace.RightName.includes(right)) && !ace.IsInherited
      );

      if (hasDangerousPerms && usersWithDangerousPerms < 10) {
        usersWithDangerousPerms++;
        examples.push(user.Properties.name);
      }
    }
  });

  if (usersWithDangerousPerms > 0) {
    findings.push({
      severity: 'HIGH',
      category: 'Dangerous Permissions',
      title: `${usersWithDangerousPerms}+ Users with Dangerous AD Permissions`,
      description: `Users have non-inherited dangerous permissions (GenericAll, WriteDacl, etc.) that can be exploited for privilege escalation. Examples: ${examples.slice(0, 5).join(', ')}`,
      impact: 'These permissions can be chained to escalate to Domain Admin or compromise high-value targets.',
      remediation: 'Audit and remove unnecessary permissions. Implement least privilege access controls. Use BloodHound to map attack paths.',
    });
  }

  return findings;
}

function analyzeHighValueTargets(data: BloodHoundData): Finding[] {
  const findings: Finding[] = [];

  let highValueCount = 0;

  if (data.users) {
    highValueCount += data.users.users.filter(u => u.Properties.highvalue && u.Properties.enabled).length;
  }

  if (data.computers) {
    highValueCount += data.computers.computers.filter(c => c.Properties.highvalue && c.Properties.enabled).length;
  }

  if (data.groups) {
    highValueCount += data.groups.groups.filter(g => g.Properties.highvalue).length;
  }

  if (highValueCount > 0) {
    findings.push({
      severity: 'INFO',
      category: 'High-Value Assets',
      title: `${highValueCount} High-Value Assets Identified`,
      description: `BloodHound has identified ${highValueCount} high-value assets (privileged accounts, critical servers, administrative groups)`,
      impact: 'These assets are primary targets for attackers. Focus security efforts on protecting these.',
      remediation: 'Use BloodHound to identify attack paths to these assets. Implement additional monitoring and controls for high-value targets.',
    });
  }

  return findings;
}

function analyzeDormantAdmins(users: BloodHoundUser[]): Finding[] {
  const findings: Finding[] = [];

  const now = Date.now();
  const ninetyDaysAgo = now - (90 * 24 * 60 * 60 * 1000);

  const dormantAdmins = users.filter(u =>
    u.Properties.enabled &&
    u.Properties.admincount &&
    u.Properties.lastlogon &&
    u.Properties.lastlogon < ninetyDaysAgo / 1000  // BloodHound uses Unix timestamp
  );

  if (dormantAdmins.length > 0) {
    findings.push({
      severity: 'HIGH',
      category: 'Dormant Privileged Accounts',
      title: `${dormantAdmins.length} Dormant Administrative Accounts`,
      description: `Privileged accounts have not logged in for 90+ days: ${dormantAdmins.slice(0, 5).map(u => u.Properties.name).join(', ')}${dormantAdmins.length > 5 ? '...' : ''}`,
      impact: 'Dormant privileged accounts are attractive targets for attackers and may indicate compromised or forgotten accounts.',
      remediation: 'Review dormant admin accounts. Disable accounts no longer in use. Investigate any suspicious activity.',
      account: dormantAdmins.map(u => u.Properties.name).join(', '),
    });
  }

  return findings;
}

function analyzeGroupMembership(groups: BloodHoundGroup[]): Finding[] {
  const findings: Finding[] = [];

  const privilegedGroups = groups.filter(g =>
    g.Properties.name.toLowerCase().includes('admin') ||
    g.Properties.name.toLowerCase().includes('operator') ||
    g.Properties.highvalue
  );

  privilegedGroups.forEach(group => {
    if (group.Members && group.Members.length > 10) {
      findings.push({
        severity: 'MEDIUM',
        category: 'Group Membership',
        title: `Large Privileged Group: ${group.Properties.name}`,
        description: `${group.Properties.name} has ${group.Members.length} members, increasing attack surface`,
        impact: 'Large privileged groups make access control harder to manage and increase the number of potential compromise targets.',
        remediation: 'Review membership and remove unnecessary accounts. Use role-based access with smaller, focused groups.',
      });
    }
  });

  return findings;
}

// Main execution
try {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.error('Usage: bun run ParseBloodHound.ts <bloodhound-dir>');
    console.error('\nExpected directory structure:');
    console.error('  bloodhound-dir/');
    console.error('    ├── computers.json');
    console.error('    ├── users.json');
    console.error('    ├── groups.json');
    console.error('    └── domains.json');
    console.error('\nGenerate with SharpHound:');
    console.error('  SharpHound.exe -c All');
    process.exit(1);
  }

  const bloodhoundDir = args[0];

  if (!existsSync(bloodhoundDir)) {
    console.error(`Error: Directory not found: ${bloodhoundDir}`);
    process.exit(1);
  }

  console.log('\n🔍 Parsing BloodHound Data...\n');

  // Load BloodHound JSON files
  const data: BloodHoundData = {};

  const usersFile = readdirSync(bloodhoundDir).find(f => f.endsWith('_users.json'));
  const computersFile = readdirSync(bloodhoundDir).find(f => f.endsWith('_computers.json'));
  const groupsFile = readdirSync(bloodhoundDir).find(f => f.endsWith('_groups.json'));

  if (usersFile) {
    data.users = JSON.parse(readFileSync(join(bloodhoundDir, usersFile), 'utf-8'));
    console.log(`✓ Loaded ${data.users?.users?.length || 0} users`);
  }

  if (computersFile) {
    data.computers = JSON.parse(readFileSync(join(bloodhoundDir, computersFile), 'utf-8'));
    console.log(`✓ Loaded ${data.computers?.computers?.length || 0} computers`);
  }

  if (groupsFile) {
    data.groups = JSON.parse(readFileSync(join(bloodhoundDir, groupsFile), 'utf-8'));
    console.log(`✓ Loaded ${data.groups?.groups?.length || 0} groups`);
  }

  if (!data.users && !data.computers && !data.groups) {
    console.error('Error: No valid BloodHound data files found');
    process.exit(1);
  }

  console.log('\n🔎 Analyzing BloodHound Data...\n');

  // Run all analyses
  const allFindings: Finding[] = [];

  if (data.users) {
    allFindings.push(...analyzeKerberoastableAccounts(data.users.users));
    allFindings.push(...analyzeASREPRoastable(data.users.users));
    allFindings.push(...analyzeDangerousPermissions(data.users.users));
    allFindings.push(...analyzeDormantAdmins(data.users.users));
  }

  if (data.computers) {
    allFindings.push(...analyzeUnconstrainedDelegation(data.computers.computers));
    allFindings.push(...analyzeLAPSCoverage(data.computers.computers));
  }

  if (data.groups) {
    allFindings.push(...analyzeGroupMembership(data.groups.groups));
  }

  allFindings.push(...analyzeHighValueTargets(data));

  // Output findings in assessment tool format
  console.log('═══════════════════════════════════════════════════════════');
  console.log('   BLOODHOUND ANALYSIS');
  console.log('═══════════════════════════════════════════════════════════\n');

  const summary = allFindings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  console.log('SUMMARY:');
  console.log(`  🔴 CRITICAL: ${summary.CRITICAL || 0}`);
  console.log(`  🟠 HIGH:     ${summary.HIGH || 0}`);
  console.log(`  🟡 MEDIUM:   ${summary.MEDIUM || 0}`);
  console.log(`  🔵 LOW:      ${summary.LOW || 0}`);
  console.log(`  ⚪ INFO:     ${summary.INFO || 0}`);
  console.log(`\n  Total Findings: ${allFindings.length}\n`);

  console.log('═══════════════════════════════════════════════════════════\n');

  // Sort by severity
  const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  allFindings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  allFindings.forEach(finding => {
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

  // Exit with appropriate code
  const hasCritical = allFindings.some(f => f.severity === 'CRITICAL');
  process.exit(hasCritical ? 1 : 0);
} catch (error) {
  console.error('Error:', error);
  process.exit(1);
}
