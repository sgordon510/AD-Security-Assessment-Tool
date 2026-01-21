// Gap Analyzer
// Permutation-based analysis to find coverage gaps in CA policies
// Inspired by CA Optics approach

import type {
  ConditionalAccessPolicy,
  Finding,
  ClientAppType,
  DevicePlatform,
} from '../types';
import { WELL_KNOWN_IDS, PRIVILEGED_ROLES, LEGACY_AUTH_CLIENT_TYPES } from '../types';

let findingCounter = 0;
function generateFindingId(): string {
  return `GAP-${String(++findingCounter).padStart(3, '0')}`;
}

// ============================================================================
// Types for Gap Analysis
// ============================================================================

interface AccessScenario {
  userType: 'all' | 'admins' | 'guests' | 'members';
  appType: 'all' | 'office365' | 'azureManagement' | 'adminPortals' | 'other';
  clientApp: ClientAppType;
  platform: DevicePlatform | 'all';
  location: 'all' | 'trusted' | 'untrusted';
  riskLevel: 'none' | 'low' | 'medium' | 'high';
}

interface PolicyMatch {
  policy: ConditionalAccessPolicy;
  action: 'mfa' | 'block' | 'compliantDevice' | 'grant' | 'none';
}

interface GapResult {
  scenario: AccessScenario;
  matchedPolicies: PolicyMatch[];
  hasProtection: boolean;
  protectionLevel: 'strong' | 'moderate' | 'weak' | 'none';
}

// ============================================================================
// Scenario Evaluation
// ============================================================================

function evaluateScenarioAgainstPolicy(
  scenario: AccessScenario,
  policy: ConditionalAccessPolicy
): PolicyMatch | null {
  // Policy must be enabled
  if (policy.state !== 'enabled') {
    return null;
  }

  // Check user conditions
  if (!matchesUserCondition(scenario, policy)) {
    return null;
  }

  // Check application conditions
  if (!matchesApplicationCondition(scenario, policy)) {
    return null;
  }

  // Check client app type
  if (!matchesClientAppCondition(scenario, policy)) {
    return null;
  }

  // Check platform
  if (!matchesPlatformCondition(scenario, policy)) {
    return null;
  }

  // Check location (simplified)
  if (!matchesLocationCondition(scenario, policy)) {
    return null;
  }

  // Check risk level
  if (!matchesRiskCondition(scenario, policy)) {
    return null;
  }

  // Determine action
  const action = determineAction(policy);

  return { policy, action };
}

function matchesUserCondition(
  scenario: AccessScenario,
  policy: ConditionalAccessPolicy
): boolean {
  const users = policy.conditions.users;
  if (!users) return true; // No user condition = matches all

  const includeUsers = users.includeUsers || [];
  const includeGroups = users.includeGroups || [];
  const includeRoles = users.includeRoles || [];

  // Check if policy includes this user type
  if (includeUsers.includes('All')) {
    return true;
  }

  if (scenario.userType === 'admins') {
    // Check if any admin roles are included
    const hasAdminRoles = includeRoles.some((role) =>
      PRIVILEGED_ROLES.includes(role)
    );
    if (hasAdminRoles || includeUsers.includes('All')) {
      return true;
    }
  }

  if (scenario.userType === 'guests') {
    if (
      includeUsers.includes('GuestsOrExternalUsers') ||
      users.includeGuestsOrExternalUsers
    ) {
      return true;
    }
  }

  if (scenario.userType === 'members' || scenario.userType === 'all') {
    // Generic match for non-specific targeting
    return includeUsers.includes('All');
  }

  return false;
}

function matchesApplicationCondition(
  scenario: AccessScenario,
  policy: ConditionalAccessPolicy
): boolean {
  const apps = policy.conditions.applications;
  if (!apps) return true;

  const includeApps = apps.includeApplications || [];

  if (includeApps.includes('All')) {
    return true;
  }

  switch (scenario.appType) {
    case 'all':
      return includeApps.includes('All');
    case 'office365':
      return (
        includeApps.includes('All') ||
        includeApps.includes('Office365') ||
        includeApps.includes('00000002-0000-0ff1-ce00-000000000000') // Office 365 Exchange
      );
    case 'azureManagement':
      return (
        includeApps.includes('All') ||
        includeApps.includes('797f4846-ba00-4fd7-ba43-dac1f8f63013')
      );
    case 'adminPortals':
      return (
        includeApps.includes('All') ||
        includeApps.includes('MicrosoftAdminPortals')
      );
    default:
      return includeApps.includes('All');
  }
}

function matchesClientAppCondition(
  scenario: AccessScenario,
  policy: ConditionalAccessPolicy
): boolean {
  const clientTypes = policy.conditions.clientAppTypes;

  // No client type condition = matches all
  if (!clientTypes || clientTypes.length === 0) {
    return true;
  }

  // 'all' matches everything
  if (clientTypes.includes('all')) {
    return true;
  }

  return clientTypes.includes(scenario.clientApp);
}

function matchesPlatformCondition(
  scenario: AccessScenario,
  policy: ConditionalAccessPolicy
): boolean {
  const platforms = policy.conditions.platforms;

  // No platform condition = matches all
  if (!platforms) {
    return true;
  }

  const includePlatforms = platforms.includePlatforms || [];
  const excludePlatforms = platforms.excludePlatforms || [];

  if (scenario.platform === 'all') {
    return includePlatforms.includes('all') || includePlatforms.length === 0;
  }

  if (excludePlatforms.includes(scenario.platform)) {
    return false;
  }

  return (
    includePlatforms.includes('all') ||
    includePlatforms.includes(scenario.platform)
  );
}

function matchesLocationCondition(
  scenario: AccessScenario,
  policy: ConditionalAccessPolicy
): boolean {
  const locations = policy.conditions.locations;

  // No location condition = matches all
  if (!locations) {
    return true;
  }

  const includeLocations = locations.includeLocations || [];
  const excludeLocations = locations.excludeLocations || [];

  if (includeLocations.includes('All')) {
    if (scenario.location === 'trusted' && excludeLocations.includes('AllTrusted')) {
      return false;
    }
    return true;
  }

  if (scenario.location === 'trusted') {
    return includeLocations.includes('AllTrusted');
  }

  return true;
}

function matchesRiskCondition(
  scenario: AccessScenario,
  policy: ConditionalAccessPolicy
): boolean {
  const signInRisk = policy.conditions.signInRiskLevels || [];

  // No risk condition = matches all
  if (signInRisk.length === 0) {
    return true;
  }

  // Policy with risk condition only applies when risk matches
  return signInRisk.includes(scenario.riskLevel as any);
}

function determineAction(policy: ConditionalAccessPolicy): PolicyMatch['action'] {
  const controls = policy.grantControls?.builtInControls || [];

  if (controls.includes('block')) {
    return 'block';
  }

  if (controls.includes('mfa')) {
    return 'mfa';
  }

  if (controls.includes('compliantDevice')) {
    return 'compliantDevice';
  }

  if (controls.length > 0) {
    return 'grant';
  }

  return 'none';
}

// ============================================================================
// Gap Analysis
// ============================================================================

function analyzeScenario(
  scenario: AccessScenario,
  policies: ConditionalAccessPolicy[]
): GapResult {
  const matchedPolicies: PolicyMatch[] = [];

  for (const policy of policies) {
    const match = evaluateScenarioAgainstPolicy(scenario, policy);
    if (match) {
      matchedPolicies.push(match);
    }
  }

  // Determine protection level
  let hasProtection = false;
  let protectionLevel: GapResult['protectionLevel'] = 'none';

  if (matchedPolicies.some((m) => m.action === 'block')) {
    hasProtection = true;
    protectionLevel = 'strong';
  } else if (matchedPolicies.some((m) => m.action === 'mfa')) {
    hasProtection = true;
    protectionLevel = 'strong';
  } else if (matchedPolicies.some((m) => m.action === 'compliantDevice')) {
    hasProtection = true;
    protectionLevel = 'moderate';
  } else if (matchedPolicies.some((m) => m.action === 'grant')) {
    hasProtection = true;
    protectionLevel = 'weak';
  }

  return {
    scenario,
    matchedPolicies,
    hasProtection,
    protectionLevel,
  };
}

function generateScenarios(): AccessScenario[] {
  const scenarios: AccessScenario[] = [];

  const userTypes: AccessScenario['userType'][] = ['admins', 'members', 'guests'];
  const appTypes: AccessScenario['appType'][] = [
    'all',
    'office365',
    'azureManagement',
    'adminPortals',
  ];
  const clientApps: ClientAppType[] = [
    'browser',
    'mobileAppsAndDesktopClients',
    'exchangeActiveSync',
    'other',
  ];
  const locations: AccessScenario['location'][] = ['trusted', 'untrusted'];

  // Generate key scenarios (not full cartesian product to keep it manageable)
  for (const userType of userTypes) {
    for (const appType of appTypes) {
      for (const clientApp of clientApps) {
        for (const location of locations) {
          scenarios.push({
            userType,
            appType,
            clientApp,
            platform: 'all',
            location,
            riskLevel: 'none',
          });
        }
      }
    }
  }

  // Add high-risk scenarios
  for (const userType of userTypes) {
    scenarios.push({
      userType,
      appType: 'all',
      clientApp: 'browser',
      platform: 'all',
      location: 'untrusted',
      riskLevel: 'high',
    });
  }

  return scenarios;
}

// ============================================================================
// Main Export
// ============================================================================

export function analyzeGaps(
  policies: ConditionalAccessPolicy[]
): Finding[] {
  findingCounter = 0;
  const findings: Finding[] = [];
  const enabledPolicies = policies.filter((p) => p.state === 'enabled');

  if (enabledPolicies.length === 0) {
    findings.push({
      id: generateFindingId(),
      severity: 'CRITICAL',
      category: 'Coverage Gap',
      title: 'No Enabled Conditional Access Policies',
      description:
        'The tenant has no enabled CA policies. All access scenarios are unprotected.',
      impact: 'No dynamic access controls are enforced',
      remediation: 'Implement CA policies following security best practices',
    });
    return findings;
  }

  const scenarios = generateScenarios();
  const gapResults: GapResult[] = [];

  for (const scenario of scenarios) {
    const result = analyzeScenario(scenario, enabledPolicies);
    if (!result.hasProtection) {
      gapResults.push(result);
    }
  }

  // Categorize and report gaps

  // 1. Admin gaps (most critical)
  const adminGaps = gapResults.filter((r) => r.scenario.userType === 'admins');
  if (adminGaps.length > 0) {
    const adminLegacyAuthGaps = adminGaps.filter((r) =>
      LEGACY_AUTH_CLIENT_TYPES.includes(r.scenario.clientApp)
    );
    const adminModernAuthGaps = adminGaps.filter(
      (r) => !LEGACY_AUTH_CLIENT_TYPES.includes(r.scenario.clientApp)
    );

    if (adminLegacyAuthGaps.length > 0) {
      findings.push({
        id: generateFindingId(),
        severity: 'CRITICAL',
        category: 'Coverage Gap',
        title: 'Administrators Can Use Legacy Authentication',
        description: `${adminLegacyAuthGaps.length} scenarios allow admin access via legacy authentication without protection`,
        impact:
          'Admins can authenticate using protocols that bypass MFA, enabling credential attacks',
        remediation:
          'Block legacy authentication for all administrator accounts',
      });
    }

    if (adminModernAuthGaps.length > 0) {
      const gapSummary = summarizeGaps(adminModernAuthGaps);
      findings.push({
        id: generateFindingId(),
        severity: 'CRITICAL',
        category: 'Coverage Gap',
        title: 'Administrator Access Without MFA',
        description: `${adminModernAuthGaps.length} scenarios allow admin access without MFA requirement: ${gapSummary}`,
        impact:
          'Admin accounts can access resources without strong authentication',
        remediation:
          'Create CA policy requiring MFA for all admin roles across all applications',
      });
    }
  }

  // 2. Guest user gaps
  const guestGaps = gapResults.filter((r) => r.scenario.userType === 'guests');
  if (guestGaps.length > 0) {
    const modernAuthGuestGaps = guestGaps.filter(
      (r) => !LEGACY_AUTH_CLIENT_TYPES.includes(r.scenario.clientApp)
    );
    if (modernAuthGuestGaps.length > 0) {
      findings.push({
        id: generateFindingId(),
        severity: 'HIGH',
        category: 'Coverage Gap',
        title: 'Guest Users Without MFA Requirement',
        description: `${modernAuthGuestGaps.length} scenarios allow guest access without MFA`,
        impact:
          'External users can access resources without strong authentication',
        remediation: 'Create CA policy requiring MFA for all guest users',
      });
    }
  }

  // 3. Legacy auth gaps for all users
  const legacyAuthGaps = gapResults.filter((r) =>
    LEGACY_AUTH_CLIENT_TYPES.includes(r.scenario.clientApp)
  );
  if (legacyAuthGaps.length > 0) {
    findings.push({
      id: generateFindingId(),
      severity: 'HIGH',
      category: 'Coverage Gap',
      title: 'Legacy Authentication Not Fully Blocked',
      description: `${legacyAuthGaps.length} scenarios allow legacy authentication access`,
      impact:
        'Legacy auth bypasses MFA and modern security controls',
      remediation:
        'Block legacy authentication for all users and all applications',
    });
  }

  // 4. Azure Management gaps
  const azureMgmtGaps = gapResults.filter(
    (r) => r.scenario.appType === 'azureManagement'
  );
  if (azureMgmtGaps.length > 0) {
    const modernGaps = azureMgmtGaps.filter(
      (r) => !LEGACY_AUTH_CLIENT_TYPES.includes(r.scenario.clientApp)
    );
    if (modernGaps.length > 0) {
      findings.push({
        id: generateFindingId(),
        severity: 'HIGH',
        category: 'Coverage Gap',
        title: 'Azure Management Access Without Protection',
        description: `${modernGaps.length} scenarios allow Azure Management access without MFA`,
        impact: 'Azure subscriptions and resources may be accessible without verification',
        remediation:
          'Create CA policy requiring MFA for Azure Management application',
      });
    }
  }

  // 5. Admin portal gaps
  const adminPortalGaps = gapResults.filter(
    (r) => r.scenario.appType === 'adminPortals'
  );
  if (adminPortalGaps.length > 0) {
    const modernGaps = adminPortalGaps.filter(
      (r) => !LEGACY_AUTH_CLIENT_TYPES.includes(r.scenario.clientApp)
    );
    if (modernGaps.length > 0) {
      findings.push({
        id: generateFindingId(),
        severity: 'HIGH',
        category: 'Coverage Gap',
        title: 'Admin Portals Accessible Without Protection',
        description: `${modernGaps.length} scenarios allow admin portal access without MFA`,
        impact:
          'Administrative portals (Azure, M365, Entra) accessible without strong auth',
        remediation:
          'Create CA policy requiring MFA for Microsoft Admin Portals',
      });
    }
  }

  // 6. High-risk sign-in gaps
  const highRiskGaps = gapResults.filter(
    (r) => r.scenario.riskLevel === 'high'
  );
  if (highRiskGaps.length > 0) {
    findings.push({
      id: generateFindingId(),
      severity: 'MEDIUM',
      category: 'Coverage Gap',
      title: 'High-Risk Sign-ins Not Protected',
      description: `${highRiskGaps.length} high-risk scenarios have no additional protection`,
      impact:
        'Sign-ins flagged as high risk are not automatically challenged or blocked',
      remediation:
        'Create risk-based CA policies requiring MFA for high-risk sign-ins',
    });
  }

  // 7. General coverage gaps
  const generalMemberGaps = gapResults.filter(
    (r) =>
      r.scenario.userType === 'members' &&
      !LEGACY_AUTH_CLIENT_TYPES.includes(r.scenario.clientApp) &&
      r.scenario.appType === 'all'
  );
  if (generalMemberGaps.length > 0) {
    findings.push({
      id: generateFindingId(),
      severity: 'MEDIUM',
      category: 'Coverage Gap',
      title: 'Standard Users Without Universal MFA',
      description: `${generalMemberGaps.length} scenarios allow member access to all apps without MFA`,
      impact: 'Regular users may access corporate resources without MFA',
      remediation:
        'Create CA policy requiring MFA for all users on all cloud apps',
    });
  }

  // Summary finding if many gaps
  const totalGaps = gapResults.length;
  if (totalGaps > 20) {
    findings.push({
      id: generateFindingId(),
      severity: 'HIGH',
      category: 'Coverage Gap',
      title: 'Significant Policy Coverage Gaps Detected',
      description: `Analysis identified ${totalGaps} access scenarios without CA policy protection`,
      impact:
        'Multiple access paths exist without security controls',
      remediation:
        'Review and implement comprehensive CA policies covering all user types, apps, and client types',
    });
  }

  return findings;
}

function summarizeGaps(gaps: GapResult[]): string {
  const apps = [...new Set(gaps.map((g) => g.scenario.appType))];
  const clients = [...new Set(gaps.map((g) => g.scenario.clientApp))];

  const parts: string[] = [];
  if (apps.length > 0) {
    parts.push(`apps: ${apps.join(', ')}`);
  }
  if (clients.length > 0) {
    parts.push(`clients: ${clients.join(', ')}`);
  }

  return parts.join('; ') || 'various scenarios';
}
