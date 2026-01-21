// Azure Conditional Access Policy Analyzer - Type Definitions
// Based on Microsoft Graph API ConditionalAccessPolicy resource type

// ============================================================================
// Microsoft Graph CA Policy Types
// ============================================================================

export interface ConditionalAccessPolicy {
  id: string;
  displayName: string;
  state: 'enabled' | 'disabled' | 'enabledForReportingButNotEnforced';
  createdDateTime?: string;
  modifiedDateTime?: string;
  conditions: ConditionalAccessConditionSet;
  grantControls?: ConditionalAccessGrantControls;
  sessionControls?: ConditionalAccessSessionControls;
}

export interface ConditionalAccessConditionSet {
  users?: ConditionalAccessUsers;
  applications?: ConditionalAccessApplications;
  clientAppTypes?: ClientAppType[];
  platforms?: ConditionalAccessPlatforms;
  locations?: ConditionalAccessLocations;
  signInRiskLevels?: RiskLevel[];
  userRiskLevels?: RiskLevel[];
  deviceStates?: ConditionalAccessDeviceStates;
  devices?: ConditionalAccessDevices;
  clientApplications?: ConditionalAccessClientApplications;
  servicePrincipalRiskLevels?: RiskLevel[];
}

export interface ConditionalAccessUsers {
  includeUsers?: string[];
  excludeUsers?: string[];
  includeGroups?: string[];
  excludeGroups?: string[];
  includeRoles?: string[];
  excludeRoles?: string[];
  includeGuestsOrExternalUsers?: ConditionalAccessGuestsOrExternalUsers;
  excludeGuestsOrExternalUsers?: ConditionalAccessGuestsOrExternalUsers;
}

export interface ConditionalAccessGuestsOrExternalUsers {
  guestOrExternalUserTypes?: GuestOrExternalUserType;
  externalTenants?: ConditionalAccessExternalTenants;
}

export type GuestOrExternalUserType =
  | 'none'
  | 'internalGuest'
  | 'b2bCollaborationGuest'
  | 'b2bCollaborationMember'
  | 'b2bDirectConnectUser'
  | 'otherExternalUser'
  | 'serviceProvider';

export interface ConditionalAccessExternalTenants {
  membershipKind?: 'all' | 'enumerated' | 'unknownFutureValue';
  members?: string[];
}

export interface ConditionalAccessApplications {
  includeApplications?: string[];
  excludeApplications?: string[];
  includeUserActions?: string[];
  includeAuthenticationContextClassReferences?: string[];
  applicationFilter?: ConditionalAccessFilter;
}

export interface ConditionalAccessFilter {
  mode: 'include' | 'exclude';
  rule: string;
}

export type ClientAppType =
  | 'all'
  | 'browser'
  | 'mobileAppsAndDesktopClients'
  | 'exchangeActiveSync'
  | 'easSupported'
  | 'other';

export interface ConditionalAccessPlatforms {
  includePlatforms?: DevicePlatform[];
  excludePlatforms?: DevicePlatform[];
}

export type DevicePlatform =
  | 'all'
  | 'android'
  | 'iOS'
  | 'windows'
  | 'windowsPhone'
  | 'macOS'
  | 'linux'
  | 'unknownFutureValue';

export interface ConditionalAccessLocations {
  includeLocations?: string[];
  excludeLocations?: string[];
}

export type RiskLevel = 'low' | 'medium' | 'high' | 'hidden' | 'none' | 'unknownFutureValue';

export interface ConditionalAccessDeviceStates {
  includeStates?: string[];
  excludeStates?: string[];
}

export interface ConditionalAccessDevices {
  includeDevices?: string[];
  excludeDevices?: string[];
  deviceFilter?: ConditionalAccessFilter;
}

export interface ConditionalAccessClientApplications {
  includeServicePrincipals?: string[];
  excludeServicePrincipals?: string[];
  servicePrincipalFilter?: ConditionalAccessFilter;
}

export interface ConditionalAccessGrantControls {
  operator?: 'AND' | 'OR';
  builtInControls?: GrantControl[];
  customAuthenticationFactors?: string[];
  termsOfUse?: string[];
  authenticationStrength?: AuthenticationStrengthPolicy;
}

export type GrantControl =
  | 'block'
  | 'mfa'
  | 'compliantDevice'
  | 'domainJoinedDevice'
  | 'approvedApplication'
  | 'compliantApplication'
  | 'passwordChange'
  | 'unknownFutureValue';

export interface AuthenticationStrengthPolicy {
  id?: string;
  displayName?: string;
  allowedCombinations?: string[];
}

export interface ConditionalAccessSessionControls {
  applicationEnforcedRestrictions?: ApplicationEnforcedRestrictionsSessionControl;
  cloudAppSecurity?: CloudAppSecuritySessionControl;
  persistentBrowser?: PersistentBrowserSessionControl;
  signInFrequency?: SignInFrequencySessionControl;
  continuousAccessEvaluation?: ContinuousAccessEvaluationSessionControl;
  disableResilienceDefaults?: boolean;
  secureSignInSession?: SecureSignInSessionControl;
}

export interface ApplicationEnforcedRestrictionsSessionControl {
  isEnabled: boolean;
}

export interface CloudAppSecuritySessionControl {
  isEnabled: boolean;
  cloudAppSecurityType?: 'mcasConfigured' | 'monitorOnly' | 'blockDownloads';
}

export interface PersistentBrowserSessionControl {
  isEnabled: boolean;
  mode?: 'always' | 'never';
}

export interface SignInFrequencySessionControl {
  isEnabled: boolean;
  type?: 'days' | 'hours';
  value?: number;
  frequencyInterval?: 'timeBased' | 'everyTime';
  authenticationType?: 'primaryAndSecondaryAuthentication' | 'secondaryAuthentication';
}

export interface ContinuousAccessEvaluationSessionControl {
  mode?: 'strictEnforcement' | 'disabled' | 'unknownFutureValue';
}

export interface SecureSignInSessionControl {
  isEnabled: boolean;
}

// ============================================================================
// Named Locations Types
// ============================================================================

export interface NamedLocation {
  id: string;
  displayName: string;
  createdDateTime?: string;
  modifiedDateTime?: string;
}

export interface IpNamedLocation extends NamedLocation {
  '@odata.type': '#microsoft.graph.ipNamedLocation';
  isTrusted: boolean;
  ipRanges: IpRange[];
}

export interface CountryNamedLocation extends NamedLocation {
  '@odata.type': '#microsoft.graph.countryNamedLocation';
  countriesAndRegions: string[];
  includeUnknownCountriesAndRegions: boolean;
}

export interface IpRange {
  '@odata.type': string;
  cidrAddress?: string;
}

// ============================================================================
// Directory Objects (for resolving IDs)
// ============================================================================

export interface DirectoryObject {
  id: string;
  displayName?: string;
}

export interface User extends DirectoryObject {
  userPrincipalName?: string;
  userType?: 'Member' | 'Guest';
}

export interface Group extends DirectoryObject {
  description?: string;
  groupTypes?: string[];
  membershipRule?: string;
}

export interface DirectoryRole extends DirectoryObject {
  roleTemplateId?: string;
  description?: string;
}

export interface ServicePrincipal extends DirectoryObject {
  appId?: string;
  servicePrincipalType?: string;
}

// ============================================================================
// Analysis Types
// ============================================================================

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface Finding {
  id: string;
  severity: Severity;
  category: string;
  title: string;
  description: string;
  impact: string;
  remediation: string;
  affectedPolicies?: string[];
  references?: string[];
}

export interface AnalysisResult {
  tenantId?: string;
  analyzedAt: string;
  totalPolicies: number;
  enabledPolicies: number;
  disabledPolicies: number;
  reportOnlyPolicies: number;
  findings: Finding[];
  summary: AnalysisSummary;
}

export interface AnalysisSummary {
  securityScore: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  categoryBreakdown: Record<string, number>;
  coverageMetrics: CoverageMetrics;
}

export interface CoverageMetrics {
  mfaEnforced: boolean;
  legacyAuthBlocked: boolean;
  adminsMfaRequired: boolean;
  riskPoliciesConfigured: boolean;
  deviceComplianceRequired: boolean;
  guestAccessControlled: boolean;
}

// ============================================================================
// Well-Known IDs and Constants
// ============================================================================

export const WELL_KNOWN_IDS = {
  // Special user identifiers
  ALL_USERS: 'All',
  ALL_GUESTS: 'GuestsOrExternalUsers',

  // Special application identifiers
  ALL_APPS: 'All',
  OFFICE_365: 'Office365',
  MICROSOFT_ADMIN_PORTALS: 'MicrosoftAdminPortals',

  // Special location identifiers
  ALL_LOCATIONS: 'All',
  ALL_TRUSTED: 'AllTrusted',

  // Privileged role template IDs
  GLOBAL_ADMIN: '62e90394-69f5-4237-9190-012177145e10',
  PRIVILEGED_ROLE_ADMIN: 'e8611ab8-c189-46e8-94e1-60213ab1f814',
  PRIVILEGED_AUTH_ADMIN: '7be44c8a-adaf-4e2a-84d6-ab2649e08a13',
  SECURITY_ADMIN: '194ae4cb-b126-40b2-bd5b-6091b380977d',
  USER_ADMIN: 'fe930be7-5e62-47db-91af-98c3a49a38b1',
  EXCHANGE_ADMIN: '29232cdf-9323-42fd-ade2-1d097af3e4de',
  SHAREPOINT_ADMIN: 'f28a1f50-f6e7-4571-818b-6a12f2af6b6c',
  TEAMS_ADMIN: '69091246-20e8-4a56-aa4d-066075b2a7a8',
  BILLING_ADMIN: 'b0f54661-2d74-4c50-afa3-1ec803f12efe',
  COMPLIANCE_ADMIN: '17315797-102d-40b4-93e0-432062caca18',
  CONDITIONAL_ACCESS_ADMIN: 'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9',
  CLOUD_APP_SECURITY_ADMIN: '892c5842-a9a6-463a-8041-72aa08ca3cf6',
  APPLICATION_ADMIN: '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3',
  AUTHENTICATION_ADMIN: 'c4e39bd9-1100-46d3-8c65-fb160da0071f',
  AZURE_AD_JOINED_DEVICE_LOCAL_ADMIN: '9f06204d-73c1-4d4c-880a-6edb90606fd8',
  CLOUD_DEVICE_ADMIN: '7698a772-787b-4ac8-901f-60d6b08affd2',
  DIRECTORY_READERS: '88d8e3e3-8f55-4a1e-953a-9b9898b8876b',
  DIRECTORY_WRITERS: '9360feb5-f418-4baa-8175-e2a00bac4301',
  DOMAIN_NAME_ADMIN: '8329153b-31d0-4727-b945-745eb3bc5f31',
  DYNAMICS_365_ADMIN: '44367163-eba1-44c3-98af-f5787879f96a',
  GROUPS_ADMIN: 'fdd7a751-b60b-444a-984c-02652fe8fa1c',
  HELPDESK_ADMIN: '729827e3-9c14-49f7-bb1b-9608f156bbb8',
  INTUNE_ADMIN: '3a2c62db-5318-420d-8d74-23affee5d9d5',
  LICENSE_ADMIN: '4d6ac14f-3453-41d0-bef9-a3e0c569773a',
  MESSAGE_CENTER_PRIVACY_READER: 'ac16e43d-7b2d-40e0-ac05-243ff356ab5b',
  MESSAGE_CENTER_READER: '790c1fb9-7f7d-4f88-86a1-ef1f95c05c1b',
  PASSWORD_ADMIN: '966707d0-3269-4727-9be2-8c3a10f19b9d',
  POWER_BI_ADMIN: 'a9ea8996-122f-4c74-9520-8edcd192826c',
  POWER_PLATFORM_ADMIN: '11648597-926c-4cf3-9c36-bcebb0ba8dcc',
  PRINTER_ADMIN: '644ef478-e28f-4e28-b9dc-3fdde9aa0b1f',
  REPORTS_READER: '4a5d8f65-41da-4de4-8968-e035b65339cf',
  SEARCH_ADMIN: '0964bb5e-9bdb-4d7b-ac29-58e794862a40',
  SERVICE_SUPPORT_ADMIN: 'f023fd81-a637-4b56-95fd-791ac0226033',
  WINDOWS_365_ADMIN: '11451d60-acb2-45eb-a7d6-43d0f0125c13',
} as const;

export const PRIVILEGED_ROLES = [
  WELL_KNOWN_IDS.GLOBAL_ADMIN,
  WELL_KNOWN_IDS.PRIVILEGED_ROLE_ADMIN,
  WELL_KNOWN_IDS.PRIVILEGED_AUTH_ADMIN,
  WELL_KNOWN_IDS.SECURITY_ADMIN,
  WELL_KNOWN_IDS.USER_ADMIN,
  WELL_KNOWN_IDS.EXCHANGE_ADMIN,
  WELL_KNOWN_IDS.SHAREPOINT_ADMIN,
  WELL_KNOWN_IDS.CONDITIONAL_ACCESS_ADMIN,
  WELL_KNOWN_IDS.APPLICATION_ADMIN,
  WELL_KNOWN_IDS.AUTHENTICATION_ADMIN,
  WELL_KNOWN_IDS.INTUNE_ADMIN,
  WELL_KNOWN_IDS.CLOUD_APP_SECURITY_ADMIN,
];

export const HIGHLY_PRIVILEGED_ROLES = [
  WELL_KNOWN_IDS.GLOBAL_ADMIN,
  WELL_KNOWN_IDS.PRIVILEGED_ROLE_ADMIN,
  WELL_KNOWN_IDS.PRIVILEGED_AUTH_ADMIN,
  WELL_KNOWN_IDS.SECURITY_ADMIN,
];

// Legacy authentication client types
export const LEGACY_AUTH_CLIENT_TYPES: ClientAppType[] = [
  'exchangeActiveSync',
  'other',
];

// Modern authentication client types
export const MODERN_AUTH_CLIENT_TYPES: ClientAppType[] = [
  'browser',
  'mobileAppsAndDesktopClients',
];
