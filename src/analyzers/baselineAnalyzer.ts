// Baseline Analyzer
// Checks CA policies against Microsoft, CISA, and industry best practices
// Inspired by Maester's MT.100x tests and CISA SCuBA baselines

import type {
  ConditionalAccessPolicy,
  Finding,
  NamedLocation,
  DirectoryRole,
  User,
  Group,
} from '../types';
import {
  WELL_KNOWN_IDS,
  PRIVILEGED_ROLES,
  HIGHLY_PRIVILEGED_ROLES,
  LEGACY_AUTH_CLIENT_TYPES,
} from '../types';

let findingCounter = 0;
function generateFindingId(): string {
  return `BASELINE-${String(++findingCounter).padStart(3, '0')}`;
}

// Helper to check if a policy targets all users
function targetsAllUsers(policy: ConditionalAccessPolicy): boolean {
  return policy.conditions.users?.includeUsers?.includes('All') ?? false;
}

// Helper to check if a policy targets all cloud apps
function targetsAllApps(policy: ConditionalAccessPolicy): boolean {
  return (
    policy.conditions.applications?.includeApplications?.includes('All') ??
    false
  );
}

// Helper to check if a policy requires MFA
function requiresMfa(policy: ConditionalAccessPolicy): boolean {
  return (
    policy.grantControls?.builtInControls?.includes('mfa') ??
    false
  );
}

// Helper to check if a policy blocks access
function blocksAccess(policy: ConditionalAccessPolicy): boolean {
  return (
    policy.grantControls?.builtInControls?.includes('block') ??
    false
  );
}

// Helper to check if a policy targets admin roles
function targetsAdminRoles(policy: ConditionalAccessPolicy): boolean {
  const roles = policy.conditions.users?.includeRoles || [];
  return roles.some((role) => PRIVILEGED_ROLES.includes(role));
}

// Helper to check if a policy targets highly privileged roles
function targetsHighlyPrivilegedRoles(
  policy: ConditionalAccessPolicy
): boolean {
  const roles = policy.conditions.users?.includeRoles || [];
  return (
    roles.some((role) => HIGHLY_PRIVILEGED_ROLES.includes(role)) ||
    roles.includes(WELL_KNOWN_IDS.GLOBAL_ADMIN)
  );
}

// Helper to check if a policy targets legacy auth
function targetsLegacyAuth(policy: ConditionalAccessPolicy): boolean {
  const clientTypes = policy.conditions.clientAppTypes || [];
  return clientTypes.some((type) => LEGACY_AUTH_CLIENT_TYPES.includes(type));
}

// Helper to check for emergency access exclusions
function hasEmergencyAccessExclusions(
  policy: ConditionalAccessPolicy,
  emergencyAccounts: string[] = []
): boolean {
  const excludedUsers = policy.conditions.users?.excludeUsers || [];
  const excludedGroups = policy.conditions.users?.excludeGroups || [];

  // Check if any known emergency accounts are excluded
  if (emergencyAccounts.length > 0) {
    return emergencyAccounts.some(
      (account) =>
        excludedUsers.includes(account) || excludedGroups.includes(account)
    );
  }

  // Heuristic: at least one exclusion exists (likely emergency access)
  return excludedUsers.length > 0 || excludedGroups.length > 0;
}

export interface BaselineAnalyzerOptions {
  emergencyAccessAccounts?: string[];
  emergencyAccessGroups?: string[];
}

export function analyzeBaseline(
  policies: ConditionalAccessPolicy[],
  namedLocations: NamedLocation[] = [],
  options: BaselineAnalyzerOptions = {}
): Finding[] {
  findingCounter = 0;
  const findings: Finding[] = [];
  const enabledPolicies = policies.filter((p) => p.state === 'enabled');

  const emergencyAccounts = [
    ...(options.emergencyAccessAccounts || []),
    ...(options.emergencyAccessGroups || []),
  ];

  // ========================================================================
  // MT.1001 - Device Compliance Policy
  // ========================================================================
  const deviceCompliancePolicies = enabledPolicies.filter((p) =>
    p.grantControls?.builtInControls?.includes('compliantDevice')
  );

  if (deviceCompliancePolicies.length === 0) {
    findings.push({
      id: generateFindingId(),
      severity: 'MEDIUM',
      category: 'Baseline - Device Trust',
      title: 'No Device Compliance Policy (MT.1001)',
      description:
        'No Conditional Access policy requires device compliance. Device compliance policies ensure only managed, secure devices can access resources.',
      impact:
        'Users can access corporate resources from unmanaged or non-compliant devices',
      remediation:
        'Create a CA policy requiring device compliance for accessing sensitive applications',
      references: [
        'https://maester.dev/docs/tests/MT.1001/',
        'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-compliant-device',
      ],
    });
  }

  // ========================================================================
  // MT.1003 - All Cloud Apps Policy
  // ========================================================================
  const allAppsPolicies = enabledPolicies.filter((p) => targetsAllApps(p));

  if (allAppsPolicies.length === 0) {
    findings.push({
      id: generateFindingId(),
      severity: 'HIGH',
      category: 'Baseline - Coverage',
      title: 'No Policy Covers All Cloud Apps (MT.1003)',
      description:
        'No Conditional Access policy targets "All cloud apps". This leaves newly registered applications unprotected.',
      impact:
        'New applications added to the tenant may not have any security controls applied',
      remediation:
        'Create baseline CA policies targeting "All cloud apps" to ensure comprehensive coverage',
      references: [
        'https://maester.dev/docs/tests/MT.1003/',
        'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps',
      ],
    });
  }

  // ========================================================================
  // MT.1005 - Emergency Access Exclusions
  // ========================================================================
  const policiesWithoutEmergencyExclusion = enabledPolicies.filter(
    (p) =>
      (targetsAllUsers(p) || targetsAdminRoles(p)) &&
      !hasEmergencyAccessExclusions(p, emergencyAccounts)
  );

  if (policiesWithoutEmergencyExclusion.length > 0) {
    findings.push({
      id: generateFindingId(),
      severity: 'HIGH',
      category: 'Baseline - Emergency Access',
      title: 'Policies Missing Emergency Access Exclusions (MT.1005)',
      description: `${policiesWithoutEmergencyExclusion.length} policies targeting all users or admins do not exclude emergency access accounts: ${policiesWithoutEmergencyExclusion.map((p) => p.displayName).join(', ')}`,
      impact:
        'Emergency/break-glass accounts may be locked out during CA policy enforcement failures or misconfigurations',
      remediation:
        'Create dedicated emergency access accounts and exclude them from all CA policies',
      affectedPolicies: policiesWithoutEmergencyExclusion.map(
        (p) => p.displayName
      ),
      references: [
        'https://maester.dev/docs/tests/MT.1005/',
        'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access',
      ],
    });
  }

  // ========================================================================
  // MT.1006 - MFA for Admin Roles
  // ========================================================================
  const adminMfaPolicies = enabledPolicies.filter(
    (p) =>
      (targetsAdminRoles(p) || targetsAllUsers(p)) &&
      requiresMfa(p)
  );

  if (adminMfaPolicies.length === 0) {
    findings.push({
      id: generateFindingId(),
      severity: 'CRITICAL',
      category: 'Baseline - Admin Protection',
      title: 'No MFA Policy for Admin Roles (MT.1006)',
      description:
        'No Conditional Access policy requires MFA for users with administrator roles',
      impact:
        'Admin accounts are vulnerable to password-based attacks and account takeover',
      remediation:
        'Create a CA policy requiring MFA for all privileged directory roles',
      references: [
        'https://maester.dev/docs/tests/MT.1006/',
        'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-admin-mfa',
      ],
    });
  }

  // ========================================================================
  // MT.1007 - MFA for All Users
  // ========================================================================
  const allUsersMfaPolicies = enabledPolicies.filter(
    (p) => targetsAllUsers(p) && targetsAllApps(p) && requiresMfa(p)
  );

  if (allUsersMfaPolicies.length === 0) {
    findings.push({
      id: generateFindingId(),
      severity: 'HIGH',
      category: 'Baseline - MFA',
      title: 'No MFA Policy for All Users (MT.1007)',
      description:
        'No Conditional Access policy requires MFA for all users across all cloud apps',
      impact:
        'Users may access resources without strong authentication, increasing compromise risk',
      remediation:
        'Create a CA policy requiring MFA for all users on all cloud apps',
      references: [
        'https://maester.dev/docs/tests/MT.1007/',
        'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-all-users-mfa',
      ],
    });
  }

  // ========================================================================
  // MT.1008 - MFA for Azure Management
  // ========================================================================
  const azureManagementMfaPolicies = enabledPolicies.filter((p) => {
    const apps = p.conditions.applications?.includeApplications || [];
    const targetsAzureMgmt =
      apps.includes('797f4846-ba00-4fd7-ba43-dac1f8f63013') || // Azure Management
      apps.includes('All');
    return targetsAzureMgmt && requiresMfa(p);
  });

  if (azureManagementMfaPolicies.length === 0) {
    findings.push({
      id: generateFindingId(),
      severity: 'HIGH',
      category: 'Baseline - Azure Protection',
      title: 'No MFA Policy for Azure Management (MT.1008)',
      description:
        'No Conditional Access policy requires MFA for Azure Management portal/API access',
      impact:
        'Azure subscriptions and resources may be accessible without strong authentication',
      remediation:
        'Create a CA policy requiring MFA for the Azure Management application',
      references: [
        'https://maester.dev/docs/tests/MT.1008/',
        'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-azure-management',
      ],
    });
  }

  // ========================================================================
  // MT.1009/MT.1010 - Block Legacy Authentication
  // ========================================================================
  const legacyAuthBlockPolicies = enabledPolicies.filter(
    (p) => targetsLegacyAuth(p) && blocksAccess(p) && targetsAllUsers(p)
  );

  if (legacyAuthBlockPolicies.length === 0) {
    findings.push({
      id: generateFindingId(),
      severity: 'HIGH',
      category: 'Baseline - Legacy Auth',
      title: 'Legacy Authentication Not Blocked (MT.1009/MT.1010)',
      description:
        'No Conditional Access policy blocks legacy authentication protocols for all users',
      impact:
        'Legacy auth bypasses MFA and is commonly exploited in password spray attacks',
      remediation:
        'Create a CA policy blocking legacy authentication (Exchange ActiveSync, other clients)',
      references: [
        'https://maester.dev/docs/tests/MT.1010/',
        'https://learn.microsoft.com/en-us/entra/identity/conditional-access/block-legacy-authentication',
      ],
    });
  }

  // ========================================================================
  // MT.1011 - Secure Security Info Registration
  // ========================================================================
  const securityInfoPolicies = enabledPolicies.filter((p) => {
    const userActions =
      p.conditions.applications?.includeUserActions || [];
    return userActions.includes(
      'urn:user:registersecurityinfo'
    );
  });

  const secureSecurityInfoPolicies = securityInfoPolicies.filter((p) => {
    const locations = p.conditions.locations;
    const requiresCompliance =
      p.grantControls?.builtInControls?.includes('compliantDevice');
    const requiresTrustedLocation =
      locations?.includeLocations?.includes('AllTrusted') ||
      (locations?.excludeLocations?.length ?? 0) > 0;
    return requiresCompliance || requiresTrustedLocation || requiresMfa(p);
  });

  if (secureSecurityInfoPolicies.length === 0) {
    findings.push({
      id: generateFindingId(),
      severity: 'MEDIUM',
      category: 'Baseline - Registration Security',
      title: 'Security Info Registration Not Protected (MT.1011)',
      description:
        'No policy secures security info registration (MFA method enrollment) with location or device requirements',
      impact:
        'Attackers with stolen credentials could register their own MFA methods',
      remediation:
        'Create a CA policy requiring trusted location or compliant device for security info registration',
      references: [
        'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-registration',
      ],
    });
  }

  // ========================================================================
  // MT.1012 - MFA for Risky Sign-ins
  // ========================================================================
  const riskySignInPolicies = enabledPolicies.filter((p) => {
    const riskLevels = p.conditions.signInRiskLevels || [];
    return riskLevels.length > 0 && (requiresMfa(p) || blocksAccess(p));
  });

  if (riskySignInPolicies.length === 0) {
    findings.push({
      id: generateFindingId(),
      severity: 'MEDIUM',
      category: 'Baseline - Risk Policies',
      title: 'No Policy for Risky Sign-ins (MT.1012)',
      description:
        'No Conditional Access policy requires MFA or blocks access for risky sign-ins',
      impact:
        'Sign-ins flagged as risky by Identity Protection are not automatically mitigated',
      remediation:
        'Create a CA policy requiring MFA for medium/high risk sign-ins',
      references: [
        'https://maester.dev/docs/tests/MT.1012/',
        'https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-configure-risk-policies',
      ],
    });
  }

  // ========================================================================
  // MT.1013 - Password Change for High Risk Users
  // ========================================================================
  const userRiskPolicies = enabledPolicies.filter((p) => {
    const riskLevels = p.conditions.userRiskLevels || [];
    const requiresPasswordChange =
      p.grantControls?.builtInControls?.includes('passwordChange');
    return riskLevels.includes('high') && (requiresPasswordChange || blocksAccess(p));
  });

  if (userRiskPolicies.length === 0) {
    findings.push({
      id: generateFindingId(),
      severity: 'MEDIUM',
      category: 'Baseline - Risk Policies',
      title: 'No Password Change for High Risk Users (MT.1013)',
      description:
        'No Conditional Access policy requires password change for users flagged as high risk',
      impact:
        'Compromised accounts identified by Identity Protection are not forced to remediate',
      remediation:
        'Create a CA policy requiring password change for high risk users',
      references: [
        'https://maester.dev/docs/tests/MT.1013/',
        'https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-configure-risk-policies',
      ],
    });
  }

  // ========================================================================
  // MT.1052 - Device Code Flow Protection
  // ========================================================================
  const deviceCodePolicies = enabledPolicies.filter((p) => {
    // Check for authentication flows condition (newer API)
    const authFlows = (p.conditions as any).authenticationFlows;
    if (authFlows?.transferMethods?.includes('deviceCodeFlow')) {
      return true;
    }
    // Heuristic: policies blocking unmanaged devices may help
    return false;
  });

  // This is a newer feature, so we make it informational
  if (deviceCodePolicies.length === 0) {
    findings.push({
      id: generateFindingId(),
      severity: 'LOW',
      category: 'Baseline - Phishing Resistance',
      title: 'Device Code Flow Not Specifically Protected (MT.1052)',
      description:
        'No Conditional Access policy specifically targets the device code authentication flow',
      impact:
        'Device code flow can be abused in phishing attacks to steal tokens',
      remediation:
        'Consider creating a CA policy to block or require MFA for device code flow',
      references: [
        'https://maester.dev/docs/tests/MT.1052/',
        'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-conditions',
      ],
    });
  }

  // ========================================================================
  // CISA SCuBA - Guest User MFA
  // ========================================================================
  const guestMfaPolicies = enabledPolicies.filter((p) => {
    const includesGuests =
      p.conditions.users?.includeGuestsOrExternalUsers ||
      p.conditions.users?.includeUsers?.includes('GuestsOrExternalUsers') ||
      targetsAllUsers(p);
    return includesGuests && requiresMfa(p);
  });

  if (guestMfaPolicies.length === 0) {
    findings.push({
      id: generateFindingId(),
      severity: 'HIGH',
      category: 'Baseline - External Access',
      title: 'No MFA Requirement for Guest Users (CISA)',
      description:
        'No Conditional Access policy requires MFA for guest or external users',
      impact:
        'External collaborators can access resources without strong authentication',
      remediation:
        'Create a CA policy requiring MFA for all guest and external users',
      references: [
        'https://www.cisa.gov/resources-tools/services/secure-cloud-business-applications-scuba-project',
        'https://learn.microsoft.com/en-us/entra/external-id/authentication-conditional-access',
      ],
    });
  }

  // ========================================================================
  // Zero Trust - Continuous Access Evaluation
  // ========================================================================
  const caePolicies = enabledPolicies.filter(
    (p) =>
      p.sessionControls?.continuousAccessEvaluation?.mode === 'strictEnforcement'
  );

  if (caePolicies.length === 0) {
    findings.push({
      id: generateFindingId(),
      severity: 'LOW',
      category: 'Baseline - Zero Trust',
      title: 'Continuous Access Evaluation Not Strictly Enforced',
      description:
        'No policies enable strict Continuous Access Evaluation (CAE) for real-time policy enforcement',
      impact:
        'Token revocation and policy changes may not be enforced in real-time',
      remediation:
        'Consider enabling strict CAE mode for critical applications',
      references: [
        'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation',
      ],
    });
  }

  // ========================================================================
  // Zero Trust - Phishing-Resistant MFA
  // ========================================================================
  const phishingResistantPolicies = enabledPolicies.filter((p) => {
    const authStrength = p.grantControls?.authenticationStrength;
    if (!authStrength) return false;

    // Check for phishing-resistant strength
    const strengthName = authStrength.displayName?.toLowerCase() || '';
    const allowedCombos = authStrength.allowedCombinations || [];

    return (
      strengthName.includes('phishing') ||
      allowedCombos.some(
        (combo) =>
          combo.includes('fido2') ||
          combo.includes('windowsHelloForBusiness') ||
          combo.includes('x509')
      )
    );
  });

  if (phishingResistantPolicies.length === 0) {
    findings.push({
      id: generateFindingId(),
      severity: 'MEDIUM',
      category: 'Baseline - Zero Trust',
      title: 'No Phishing-Resistant MFA Policy',
      description:
        'No Conditional Access policy enforces phishing-resistant authentication (FIDO2, Windows Hello, Certificate)',
      impact:
        'Users may use MFA methods vulnerable to real-time phishing attacks',
      remediation:
        'Create CA policies requiring phishing-resistant MFA, starting with privileged accounts',
      references: [
        'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-grant',
        'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths',
      ],
    });
  }

  // ========================================================================
  // Microsoft Recommendation - Named Locations
  // ========================================================================
  const trustedLocations = namedLocations.filter(
    (loc: any) => loc.isTrusted === true
  );

  if (trustedLocations.length === 0) {
    findings.push({
      id: generateFindingId(),
      severity: 'LOW',
      category: 'Baseline - Configuration',
      title: 'No Trusted Named Locations Configured',
      description:
        'No trusted named locations (corporate IPs, VPNs) are defined in the tenant',
      impact:
        'Cannot implement location-aware policies or reduce friction for trusted networks',
      remediation:
        'Define trusted named locations for corporate networks and known-good IP ranges',
      references: [
        'https://learn.microsoft.com/en-us/entra/identity/conditional-access/location-condition',
      ],
    });
  }

  // ========================================================================
  // Overall Policy Count Check
  // ========================================================================
  if (enabledPolicies.length === 0) {
    findings.push({
      id: generateFindingId(),
      severity: 'CRITICAL',
      category: 'Baseline - Coverage',
      title: 'No Conditional Access Policies Enabled',
      description:
        'The tenant has no enabled Conditional Access policies. This leaves the environment without dynamic access controls.',
      impact:
        'No identity-based security controls are enforced beyond basic authentication',
      remediation:
        'Implement Conditional Access policies following Microsoft and CISA best practices',
      references: [
        'https://learn.microsoft.com/en-us/entra/identity/conditional-access/plan-conditional-access',
        'https://www.cisa.gov/resources-tools/services/secure-cloud-business-applications-scuba-project',
      ],
    });
  } else if (enabledPolicies.length < 5) {
    findings.push({
      id: generateFindingId(),
      severity: 'MEDIUM',
      category: 'Baseline - Coverage',
      title: 'Limited Conditional Access Policy Coverage',
      description: `Only ${enabledPolicies.length} Conditional Access policies are enabled. A mature security posture typically requires more comprehensive coverage.`,
      impact: 'May have gaps in security coverage across different scenarios',
      remediation:
        'Review and implement additional CA policies for admin protection, device compliance, risk-based access, etc.',
      references: [
        'https://learn.microsoft.com/en-us/entra/identity/conditional-access/plan-conditional-access',
      ],
    });
  }

  return findings;
}
