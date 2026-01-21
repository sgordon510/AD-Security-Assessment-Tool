// Misconfiguration Analyzer
// Detects common CA policy misconfigurations and anti-patterns

import type {
  ConditionalAccessPolicy,
  Finding,
  NamedLocation,
  DirectoryRole,
} from '../types';
import {
  WELL_KNOWN_IDS,
  PRIVILEGED_ROLES,
  HIGHLY_PRIVILEGED_ROLES,
  LEGACY_AUTH_CLIENT_TYPES,
} from '../types';

let findingCounter = 0;
function generateFindingId(): string {
  return `MISCONFIG-${String(++findingCounter).padStart(3, '0')}`;
}

export function analyzeMisconfigurations(
  policies: ConditionalAccessPolicy[],
  namedLocations: NamedLocation[] = [],
  directoryRoles: DirectoryRole[] = []
): Finding[] {
  findingCounter = 0;
  const findings: Finding[] = [];
  const enabledPolicies = policies.filter((p) => p.state === 'enabled');
  const reportOnlyPolicies = policies.filter(
    (p) => p.state === 'enabledForReportingButNotEnforced'
  );

  // ========================================================================
  // Policy State Checks
  // ========================================================================

  // Check for report-only policies that may need enforcement
  if (reportOnlyPolicies.length > 0) {
    const longRunningReportOnly = reportOnlyPolicies.filter((p) => {
      if (!p.createdDateTime) return false;
      const created = new Date(p.createdDateTime);
      const daysSinceCreated = Math.floor(
        (Date.now() - created.getTime()) / (1000 * 60 * 60 * 24)
      );
      return daysSinceCreated > 30;
    });

    if (longRunningReportOnly.length > 0) {
      findings.push({
        id: generateFindingId(),
        severity: 'MEDIUM',
        category: 'Policy State',
        title: 'Report-Only Policies Running Over 30 Days',
        description: `${longRunningReportOnly.length} policies have been in report-only mode for over 30 days and may be ready for enforcement: ${longRunningReportOnly.map((p) => p.displayName).join(', ')}`,
        impact:
          'Security controls in report-only mode provide visibility but do not enforce protection',
        remediation:
          'Review report-only policy impact in sign-in logs and enable enforcement if results are acceptable',
        affectedPolicies: longRunningReportOnly.map((p) => p.displayName),
        references: [
          'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-report-only',
        ],
      });
    }
  }

  // Check for disabled policies
  const disabledPolicies = policies.filter((p) => p.state === 'disabled');
  if (disabledPolicies.length > 0) {
    findings.push({
      id: generateFindingId(),
      severity: 'INFO',
      category: 'Policy State',
      title: 'Disabled Conditional Access Policies',
      description: `${disabledPolicies.length} policies are disabled: ${disabledPolicies.map((p) => p.displayName).join(', ')}`,
      impact:
        'Disabled policies provide no security protection and may indicate abandoned security initiatives',
      remediation:
        'Review disabled policies and either remove them if obsolete or re-enable if still needed',
      affectedPolicies: disabledPolicies.map((p) => p.displayName),
    });
  }

  // ========================================================================
  // MFA Configuration Checks
  // ========================================================================

  // Check for policies requiring MFA
  const mfaPolicies = enabledPolicies.filter((p) =>
    p.grantControls?.builtInControls?.includes('mfa')
  );

  if (mfaPolicies.length === 0) {
    findings.push({
      id: generateFindingId(),
      severity: 'CRITICAL',
      category: 'MFA Enforcement',
      title: 'No MFA Enforcement Policies',
      description:
        'No enabled Conditional Access policies require multi-factor authentication',
      impact:
        'Without MFA enforcement, accounts are vulnerable to password spray, credential stuffing, and phishing attacks',
      remediation:
        'Create Conditional Access policies to require MFA for all users, starting with privileged accounts',
      references: [
        'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-all-users-mfa',
      ],
    });
  }

  // Check for MFA on privileged roles
  const adminMfaPolicies = enabledPolicies.filter((p) => {
    const includesPrivilegedRoles = p.conditions.users?.includeRoles?.some(
      (role) => PRIVILEGED_ROLES.includes(role)
    );
    const includesAllUsers = p.conditions.users?.includeUsers?.includes('All');
    const requiresMfa = p.grantControls?.builtInControls?.includes('mfa');

    return (includesPrivilegedRoles || includesAllUsers) && requiresMfa;
  });

  if (adminMfaPolicies.length === 0 && mfaPolicies.length > 0) {
    findings.push({
      id: generateFindingId(),
      severity: 'CRITICAL',
      category: 'Admin Protection',
      title: 'No MFA Requirement for Privileged Roles',
      description:
        'No policy specifically requires MFA for privileged administrator roles',
      impact:
        'Compromised admin accounts without MFA can lead to full tenant compromise',
      remediation:
        'Create a dedicated CA policy requiring MFA for all privileged directory roles',
      references: [
        'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-admin-mfa',
      ],
    });
  }

  // Check for policies with weak MFA - only "OR" operator
  const weakMfaPolicies = enabledPolicies.filter((p) => {
    const hasMfa = p.grantControls?.builtInControls?.includes('mfa');
    const hasOtherControls =
      p.grantControls?.builtInControls &&
      p.grantControls.builtInControls.length > 1;
    const usesOr = p.grantControls?.operator === 'OR';

    return hasMfa && hasOtherControls && usesOr;
  });

  if (weakMfaPolicies.length > 0) {
    findings.push({
      id: generateFindingId(),
      severity: 'MEDIUM',
      category: 'MFA Enforcement',
      title: 'MFA Can Be Bypassed via Alternative Controls',
      description: `${weakMfaPolicies.length} policies use OR operator allowing users to satisfy controls without MFA: ${weakMfaPolicies.map((p) => p.displayName).join(', ')}`,
      impact:
        'Users may bypass MFA by satisfying alternative grant controls like device compliance',
      remediation:
        'Consider using AND operator or authentication strengths to ensure MFA is always required',
      affectedPolicies: weakMfaPolicies.map((p) => p.displayName),
    });
  }

  // ========================================================================
  // Legacy Authentication Checks
  // ========================================================================

  // Check if legacy auth is blocked
  const legacyAuthBlockPolicies = enabledPolicies.filter((p) => {
    const targetsLegacyAuth = p.conditions.clientAppTypes?.some((type) =>
      LEGACY_AUTH_CLIENT_TYPES.includes(type)
    );
    const blocks = p.grantControls?.builtInControls?.includes('block');
    const targetsAllUsers = p.conditions.users?.includeUsers?.includes('All');
    const targetsAllApps =
      p.conditions.applications?.includeApplications?.includes('All');

    return targetsLegacyAuth && blocks && targetsAllUsers && targetsAllApps;
  });

  if (legacyAuthBlockPolicies.length === 0) {
    findings.push({
      id: generateFindingId(),
      severity: 'HIGH',
      category: 'Legacy Authentication',
      title: 'Legacy Authentication Not Blocked',
      description:
        'No policy blocks legacy authentication protocols (Basic Auth, POP3, IMAP, SMTP, etc.)',
      impact:
        'Legacy authentication bypasses MFA and modern security controls, enabling password spray attacks',
      remediation:
        'Create a CA policy to block legacy authentication for all users and all applications',
      references: [
        'https://learn.microsoft.com/en-us/entra/identity/conditional-access/block-legacy-authentication',
      ],
    });
  }

  // Check if legacy auth is blocked for admins specifically
  const adminLegacyAuthBlock = enabledPolicies.filter((p) => {
    const targetsLegacyAuth = p.conditions.clientAppTypes?.some((type) =>
      LEGACY_AUTH_CLIENT_TYPES.includes(type)
    );
    const blocks = p.grantControls?.builtInControls?.includes('block');
    const targetsAdmins =
      p.conditions.users?.includeRoles?.some((role) =>
        PRIVILEGED_ROLES.includes(role)
      ) || p.conditions.users?.includeUsers?.includes('All');

    return targetsLegacyAuth && blocks && targetsAdmins;
  });

  if (
    adminLegacyAuthBlock.length === 0 &&
    legacyAuthBlockPolicies.length === 0
  ) {
    findings.push({
      id: generateFindingId(),
      severity: 'CRITICAL',
      category: 'Legacy Authentication',
      title: 'Legacy Authentication Allowed for Administrators',
      description:
        'No policy blocks legacy authentication for privileged administrator accounts',
      impact:
        'Admin accounts using legacy auth are prime targets for password spray and credential theft',
      remediation:
        'Immediately block legacy authentication for all admin accounts',
      references: [
        'https://learn.microsoft.com/en-us/entra/identity/conditional-access/block-legacy-authentication',
      ],
    });
  }

  // ========================================================================
  // Exclusion Checks
  // ========================================================================

  // Check for overly broad user exclusions
  for (const policy of enabledPolicies) {
    const excludedUsers = policy.conditions.users?.excludeUsers || [];
    const excludedGroups = policy.conditions.users?.excludeGroups || [];

    // Flag policies with many individual user exclusions
    if (excludedUsers.length > 5) {
      findings.push({
        id: generateFindingId(),
        severity: 'MEDIUM',
        category: 'Policy Exclusions',
        title: 'Policy Has Many User Exclusions',
        description: `Policy "${policy.displayName}" excludes ${excludedUsers.length} individual users, which is difficult to maintain`,
        impact:
          'Individual user exclusions are prone to errors and may leave gaps in security coverage',
        remediation:
          'Use group-based exclusions instead of individual users for easier management',
        affectedPolicies: [policy.displayName],
      });
    }

    // Flag policies excluding admin roles from MFA
    if (policy.grantControls?.builtInControls?.includes('mfa')) {
      const excludedRoles = policy.conditions.users?.excludeRoles || [];
      const excludedPrivilegedRoles = excludedRoles.filter((role) =>
        HIGHLY_PRIVILEGED_ROLES.includes(role)
      );

      if (excludedPrivilegedRoles.length > 0) {
        findings.push({
          id: generateFindingId(),
          severity: 'CRITICAL',
          category: 'Policy Exclusions',
          title: 'Privileged Roles Excluded from MFA Policy',
          description: `Policy "${policy.displayName}" requires MFA but excludes ${excludedPrivilegedRoles.length} privileged admin roles`,
          impact:
            'Privileged accounts without MFA protection are high-value targets for attackers',
          remediation:
            'Remove admin role exclusions from MFA policies or create a separate, stronger policy for admins',
          affectedPolicies: [policy.displayName],
        });
      }
    }
  }

  // ========================================================================
  // Application Coverage Checks
  // ========================================================================

  // Check for policies only targeting specific apps (may miss others)
  const appSpecificPolicies = enabledPolicies.filter((p) => {
    const apps = p.conditions.applications?.includeApplications || [];
    return apps.length > 0 && !apps.includes('All');
  });

  const allAppsPolicies = enabledPolicies.filter((p) =>
    p.conditions.applications?.includeApplications?.includes('All')
  );

  if (allAppsPolicies.length === 0 && appSpecificPolicies.length > 0) {
    findings.push({
      id: generateFindingId(),
      severity: 'HIGH',
      category: 'Application Coverage',
      title: 'No Policy Covers All Applications',
      description:
        'All CA policies target specific applications. New applications added to the tenant may not be protected.',
      impact:
        'Newly registered applications may be accessible without security controls',
      remediation:
        'Create baseline policies targeting "All cloud apps" to ensure comprehensive coverage',
      references: [
        'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps',
      ],
    });
  }

  // ========================================================================
  // Location-Based Controls Checks
  // ========================================================================

  // Check if named locations are defined
  const trustedLocations = namedLocations.filter(
    (loc) => 'isTrusted' in loc && (loc as any).isTrusted
  );

  if (trustedLocations.length === 0) {
    findings.push({
      id: generateFindingId(),
      severity: 'MEDIUM',
      category: 'Location Controls',
      title: 'No Trusted Named Locations Defined',
      description:
        'No trusted named locations (corporate networks, VPNs) are configured',
      impact:
        'Cannot implement location-based access controls or risk-adjusted policies',
      remediation:
        'Define trusted named locations for corporate networks, VPNs, and known safe IPs',
      references: [
        'https://learn.microsoft.com/en-us/entra/identity/conditional-access/location-condition',
      ],
    });
  }

  // Check for location-based policies
  const locationPolicies = enabledPolicies.filter(
    (p) =>
      p.conditions.locations?.includeLocations?.length ||
      p.conditions.locations?.excludeLocations?.length
  );

  if (locationPolicies.length === 0 && trustedLocations.length > 0) {
    findings.push({
      id: generateFindingId(),
      severity: 'LOW',
      category: 'Location Controls',
      title: 'Named Locations Not Used in Policies',
      description:
        'Trusted named locations are defined but no CA policies use location-based conditions',
      impact:
        'Missing opportunity for defense-in-depth with location-based controls',
      remediation:
        'Consider adding location conditions to policies for admins accessing from untrusted locations',
    });
  }

  // ========================================================================
  // Risk-Based Policy Checks
  // ========================================================================

  // Check for sign-in risk policies
  const signInRiskPolicies = enabledPolicies.filter(
    (p) =>
      p.conditions.signInRiskLevels && p.conditions.signInRiskLevels.length > 0
  );

  if (signInRiskPolicies.length === 0) {
    findings.push({
      id: generateFindingId(),
      severity: 'MEDIUM',
      category: 'Risk Policies',
      title: 'No Sign-In Risk Policies Configured',
      description:
        'No Conditional Access policies evaluate sign-in risk levels from Identity Protection',
      impact:
        'Risky sign-ins (unfamiliar locations, impossible travel, etc.) are not automatically mitigated',
      remediation:
        'Create policies requiring MFA or blocking access for medium and high risk sign-ins',
      references: [
        'https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-configure-risk-policies',
      ],
    });
  }

  // Check for user risk policies
  const userRiskPolicies = enabledPolicies.filter(
    (p) => p.conditions.userRiskLevels && p.conditions.userRiskLevels.length > 0
  );

  if (userRiskPolicies.length === 0) {
    findings.push({
      id: generateFindingId(),
      severity: 'MEDIUM',
      category: 'Risk Policies',
      title: 'No User Risk Policies Configured',
      description:
        'No Conditional Access policies evaluate user risk levels from Identity Protection',
      impact:
        'Compromised user accounts are not automatically required to remediate',
      remediation:
        'Create policies requiring password change for high risk users',
      references: [
        'https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-configure-risk-policies',
      ],
    });
  }

  // ========================================================================
  // Device Compliance Checks
  // ========================================================================

  const deviceCompliancePolicies = enabledPolicies.filter((p) =>
    p.grantControls?.builtInControls?.includes('compliantDevice')
  );

  const domainJoinPolicies = enabledPolicies.filter((p) =>
    p.grantControls?.builtInControls?.includes('domainJoinedDevice')
  );

  if (
    deviceCompliancePolicies.length === 0 &&
    domainJoinPolicies.length === 0
  ) {
    findings.push({
      id: generateFindingId(),
      severity: 'MEDIUM',
      category: 'Device Controls',
      title: 'No Device Compliance Requirements',
      description:
        'No policies require device compliance or Hybrid Azure AD join',
      impact:
        'Users can access resources from unmanaged, potentially compromised devices',
      remediation:
        'Implement device compliance requirements for accessing sensitive applications',
      references: [
        'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-compliant-device',
      ],
    });
  }

  // ========================================================================
  // Session Control Checks
  // ========================================================================

  // Check for sign-in frequency controls
  const signInFrequencyPolicies = enabledPolicies.filter(
    (p) => p.sessionControls?.signInFrequency?.isEnabled
  );

  if (signInFrequencyPolicies.length === 0) {
    findings.push({
      id: generateFindingId(),
      severity: 'LOW',
      category: 'Session Controls',
      title: 'No Sign-In Frequency Controls',
      description:
        'No policies configure sign-in frequency to force re-authentication',
      impact:
        'Long-lived sessions may persist after account compromise or status change',
      remediation:
        'Consider implementing sign-in frequency controls, especially for privileged access',
      references: [
        'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-session-lifetime',
      ],
    });
  }

  // Check for persistent browser controls
  const persistentBrowserPolicies = enabledPolicies.filter(
    (p) => p.sessionControls?.persistentBrowser?.isEnabled
  );

  const adminPersistentBrowser = enabledPolicies.filter((p) => {
    const targetsAdmins =
      p.conditions.users?.includeRoles?.some((role) =>
        PRIVILEGED_ROLES.includes(role)
      ) || p.conditions.users?.includeUsers?.includes('All');
    const controlsPersistence =
      p.sessionControls?.persistentBrowser?.mode === 'never';
    return targetsAdmins && controlsPersistence;
  });

  if (adminPersistentBrowser.length === 0) {
    findings.push({
      id: generateFindingId(),
      severity: 'LOW',
      category: 'Session Controls',
      title: 'No Persistent Browser Restrictions for Admins',
      description:
        'No policy disables persistent browser sessions for privileged accounts',
      impact:
        'Admin sessions may persist on shared or unmanaged devices, increasing exposure risk',
      remediation:
        'Disable persistent browser sessions for admin accounts on unmanaged devices',
    });
  }

  // ========================================================================
  // Guest/External User Checks
  // ========================================================================

  const guestPolicies = enabledPolicies.filter((p) => {
    const includesGuests =
      p.conditions.users?.includeGuestsOrExternalUsers ||
      p.conditions.users?.includeUsers?.includes('GuestsOrExternalUsers');
    const includesAll = p.conditions.users?.includeUsers?.includes('All');
    return includesGuests || includesAll;
  });

  const guestMfaPolicies = guestPolicies.filter((p) =>
    p.grantControls?.builtInControls?.includes('mfa')
  );

  if (guestMfaPolicies.length === 0) {
    findings.push({
      id: generateFindingId(),
      severity: 'HIGH',
      category: 'Guest Access',
      title: 'No MFA Requirement for Guest Users',
      description:
        'No policy specifically requires MFA for guest or external users',
      impact:
        'Guest accounts from partner organizations may access resources without strong authentication',
      remediation:
        'Create or update policies to require MFA for all guest and external users',
      references: [
        'https://learn.microsoft.com/en-us/entra/external-id/authentication-conditional-access',
      ],
    });
  }

  // ========================================================================
  // Microsoft Admin Portal Protection
  // ========================================================================

  const adminPortalPolicies = enabledPolicies.filter((p) => {
    const targetsAdminPortals =
      p.conditions.applications?.includeApplications?.includes(
        'MicrosoftAdminPortals'
      ) || p.conditions.applications?.includeApplications?.includes('All');
    const requiresMfa = p.grantControls?.builtInControls?.includes('mfa');
    const blocks = p.grantControls?.builtInControls?.includes('block');
    return targetsAdminPortals && (requiresMfa || blocks);
  });

  if (adminPortalPolicies.length === 0) {
    findings.push({
      id: generateFindingId(),
      severity: 'HIGH',
      category: 'Admin Protection',
      title: 'Microsoft Admin Portals Not Protected',
      description:
        'No specific policy protects access to Microsoft Admin Portals (Azure, M365, Entra)',
      impact:
        'Administrative portals may be accessible without additional verification',
      remediation:
        'Create a policy requiring MFA for access to Microsoft Admin Portals',
      references: [
        'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-admin-mfa',
      ],
    });
  }

  return findings;
}
