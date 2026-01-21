#!/usr/bin/env bun
// Azure Conditional Access Policy Analyzer
// Analyzes CA policies for gaps, misconfigurations, and best practice compliance

import { readFileSync, writeFileSync, existsSync } from 'fs';
import { join } from 'path';

import type {
  ConditionalAccessPolicy,
  NamedLocation,
  Finding,
  AnalysisResult,
  AnalysisSummary,
  CoverageMetrics,
  Severity,
} from './types';

import { analyzeMisconfigurations } from './analyzers/misconfigAnalyzer';
import { analyzeBaseline } from './analyzers/baselineAnalyzer';
import { analyzeGaps } from './analyzers/gapAnalyzer';
import {
  generateHtmlReport,
  generateJsonReport,
  generateMarkdownReport,
} from './report/htmlReport';
import {
  GraphClient,
  getTokenFromAzureCli,
  checkAzureCliAuth,
  isValidAccessToken,
} from './graph/client';

// ============================================================================
// CLI Argument Parsing
// ============================================================================

interface CliArgs {
  command: 'analyze' | 'help' | 'version';
  inputFile?: string;
  outputDir?: string;
  format?: 'html' | 'json' | 'markdown' | 'all';
  tenantName?: string;
  accessToken?: string;
  fetchLive?: boolean;
  verbose?: boolean;
}

function parseArgs(): CliArgs {
  const args = process.argv.slice(2);
  const result: CliArgs = {
    command: 'analyze',
    format: 'html',
    tenantName: 'Your Organization',
    verbose: false,
    fetchLive: false,
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    switch (arg) {
      case 'help':
      case '--help':
      case '-h':
        result.command = 'help';
        break;

      case 'version':
      case '--version':
      case '-v':
        result.command = 'version';
        break;

      case '--input':
      case '-i':
        result.inputFile = args[++i];
        break;

      case '--output':
      case '-o':
        result.outputDir = args[++i];
        break;

      case '--format':
      case '-f':
        result.format = args[++i] as CliArgs['format'];
        break;

      case '--tenant':
      case '-t':
        result.tenantName = args[++i];
        break;

      case '--token':
        result.accessToken = args[++i];
        break;

      case '--live':
      case '-l':
        result.fetchLive = true;
        break;

      case '--verbose':
        result.verbose = true;
        break;

      default:
        // Treat positional arg as input file
        if (!arg.startsWith('-') && !result.inputFile) {
          result.inputFile = arg;
        }
    }
  }

  return result;
}

function showHelp(): void {
  console.log(`
Azure Conditional Access Policy Analyzer

Usage:
  bun run src/index.ts [options] [input-file]

Options:
  -i, --input <file>     Input JSON file with CA policies
  -o, --output <dir>     Output directory for reports (default: ./reports)
  -f, --format <type>    Output format: html, json, markdown, all (default: html)
  -t, --tenant <name>    Organization name for report header
  -l, --live             Fetch policies live from Microsoft Graph API
      --token <token>    Access token for Graph API (or uses Azure CLI)
      --verbose          Show detailed output
  -h, --help             Show this help message
  -v, --version          Show version

Examples:
  # Analyze from JSON file
  bun run src/index.ts -i policies.json -o ./reports -t "Contoso Inc"

  # Fetch live from Azure (requires az cli login)
  bun run src/index.ts --live -t "Contoso Inc"

  # Generate all report formats
  bun run src/index.ts -i policies.json -f all

Input JSON Format:
  {
    "policies": [...],           // ConditionalAccessPolicy[]
    "namedLocations": [...],     // Optional: NamedLocation[]
    "emergencyAccounts": [...]   // Optional: string[] of account/group IDs
  }

Export policies using Microsoft Graph PowerShell:
  Connect-MgGraph -Scopes "Policy.Read.All"
  Get-MgIdentityConditionalAccessPolicy | ConvertTo-Json -Depth 10 > policies.json
`);
}

function showVersion(): void {
  console.log('Azure CA Policy Analyzer v1.0.0');
}

// ============================================================================
// Security Score Calculation
// ============================================================================

function calculateSecurityScore(findings: Finding[]): number {
  if (findings.length === 0) return 100;

  const weights: Record<Severity, number> = {
    CRITICAL: 15,
    HIGH: 10,
    MEDIUM: 5,
    LOW: 2,
    INFO: 0,
  };

  const totalPenalty = findings.reduce(
    (sum, f) => sum + weights[f.severity],
    0
  );

  // Max penalty caps at 100
  const score = Math.max(0, 100 - Math.min(totalPenalty, 100));
  return score;
}

function calculateCoverageMetrics(
  policies: ConditionalAccessPolicy[]
): CoverageMetrics {
  const enabled = policies.filter((p) => p.state === 'enabled');

  const hasMfaPolicy = enabled.some((p) =>
    p.grantControls?.builtInControls?.includes('mfa')
  );

  const hasLegacyAuthBlock = enabled.some((p) => {
    const clientTypes = p.conditions.clientAppTypes || [];
    const blocks = p.grantControls?.builtInControls?.includes('block');
    return (
      (clientTypes.includes('exchangeActiveSync') ||
        clientTypes.includes('other')) &&
      blocks
    );
  });

  const hasAdminMfa = enabled.some((p) => {
    const roles = p.conditions.users?.includeRoles || [];
    const allUsers = p.conditions.users?.includeUsers?.includes('All');
    const hasMfa = p.grantControls?.builtInControls?.includes('mfa');
    return (roles.length > 0 || allUsers) && hasMfa;
  });

  const hasRiskPolicies = enabled.some(
    (p) =>
      (p.conditions.signInRiskLevels?.length ?? 0) > 0 ||
      (p.conditions.userRiskLevels?.length ?? 0) > 0
  );

  const hasDeviceCompliance = enabled.some((p) =>
    p.grantControls?.builtInControls?.includes('compliantDevice')
  );

  const hasGuestControl = enabled.some((p) => {
    const includesGuests =
      p.conditions.users?.includeGuestsOrExternalUsers ||
      p.conditions.users?.includeUsers?.includes('GuestsOrExternalUsers') ||
      p.conditions.users?.includeUsers?.includes('All');
    const hasMfa = p.grantControls?.builtInControls?.includes('mfa');
    return includesGuests && hasMfa;
  });

  return {
    mfaEnforced: hasMfaPolicy,
    legacyAuthBlocked: hasLegacyAuthBlock,
    adminsMfaRequired: hasAdminMfa,
    riskPoliciesConfigured: hasRiskPolicies,
    deviceComplianceRequired: hasDeviceCompliance,
    guestAccessControlled: hasGuestControl,
  };
}

// ============================================================================
// Main Analysis Function
// ============================================================================

interface AnalysisInput {
  policies: ConditionalAccessPolicy[];
  namedLocations?: NamedLocation[];
  emergencyAccounts?: string[];
}

function runAnalysis(input: AnalysisInput): AnalysisResult {
  const { policies, namedLocations = [], emergencyAccounts = [] } = input;

  const enabledPolicies = policies.filter((p) => p.state === 'enabled');
  const reportOnlyPolicies = policies.filter(
    (p) => p.state === 'enabledForReportingButNotEnforced'
  );
  const disabledPolicies = policies.filter((p) => p.state === 'disabled');

  // Run all analyzers
  const misconfigFindings = analyzeMisconfigurations(
    policies,
    namedLocations,
    []
  );

  const baselineFindings = analyzeBaseline(policies, namedLocations, {
    emergencyAccessAccounts: emergencyAccounts,
  });

  const gapFindings = analyzeGaps(policies);

  // Combine and deduplicate findings
  const allFindings = [...misconfigFindings, ...baselineFindings, ...gapFindings];

  // Remove duplicate findings (same title)
  const seenTitles = new Set<string>();
  const uniqueFindings = allFindings.filter((f) => {
    if (seenTitles.has(f.title)) {
      return false;
    }
    seenTitles.add(f.title);
    return true;
  });

  // Sort by severity
  const severityOrder: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 1,
    MEDIUM: 2,
    LOW: 3,
    INFO: 4,
  };
  uniqueFindings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  // Calculate metrics
  const securityScore = calculateSecurityScore(uniqueFindings);
  const coverageMetrics = calculateCoverageMetrics(policies);

  const criticalCount = uniqueFindings.filter((f) => f.severity === 'CRITICAL').length;
  const highCount = uniqueFindings.filter((f) => f.severity === 'HIGH').length;
  const mediumCount = uniqueFindings.filter((f) => f.severity === 'MEDIUM').length;
  const lowCount = uniqueFindings.filter((f) => f.severity === 'LOW').length;
  const infoCount = uniqueFindings.filter((f) => f.severity === 'INFO').length;

  // Category breakdown
  const categoryBreakdown: Record<string, number> = {};
  for (const finding of uniqueFindings) {
    categoryBreakdown[finding.category] =
      (categoryBreakdown[finding.category] || 0) + 1;
  }

  const summary: AnalysisSummary = {
    securityScore,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    infoCount,
    categoryBreakdown,
    coverageMetrics,
  };

  return {
    analyzedAt: new Date().toISOString(),
    totalPolicies: policies.length,
    enabledPolicies: enabledPolicies.length,
    disabledPolicies: disabledPolicies.length,
    reportOnlyPolicies: reportOnlyPolicies.length,
    findings: uniqueFindings,
    summary,
  };
}

// ============================================================================
// Main Entry Point
// ============================================================================

async function main(): Promise<void> {
  const args = parseArgs();

  if (args.command === 'help') {
    showHelp();
    process.exit(0);
  }

  if (args.command === 'version') {
    showVersion();
    process.exit(0);
  }

  console.log('\n🔍 Azure Conditional Access Policy Analyzer\n');

  let input: AnalysisInput;

  // Fetch live from Graph API
  if (args.fetchLive) {
    console.log('Fetching policies from Microsoft Graph API...\n');

    let token = args.accessToken;

    if (!token) {
      // Try Azure CLI
      const hasAzCli = await checkAzureCliAuth();
      if (!hasAzCli) {
        console.error(
          'Error: Azure CLI not authenticated. Run "az login" first or provide --token'
        );
        process.exit(1);
      }

      token = await getTokenFromAzureCli();
      if (!token) {
        console.error('Error: Failed to get access token from Azure CLI');
        process.exit(1);
      }
    }

    if (!isValidAccessToken(token)) {
      console.error('Error: Invalid or expired access token');
      process.exit(1);
    }

    try {
      const client = new GraphClient({ accessToken: token });

      const [policies, namedLocations, tenant] = await Promise.all([
        client.getConditionalAccessPolicies(),
        client.getNamedLocations(),
        client.getTenantDetails().catch(() => ({ displayName: args.tenantName })),
      ]);

      console.log(`  Fetched ${policies.length} CA policies`);
      console.log(`  Fetched ${namedLocations.length} named locations`);
      console.log(`  Tenant: ${tenant.displayName}\n`);

      input = {
        policies,
        namedLocations,
        emergencyAccounts: [],
      };

      args.tenantName = tenant.displayName || args.tenantName;
    } catch (error) {
      console.error('Error fetching from Graph API:', error);
      process.exit(1);
    }
  }
  // Load from file
  else if (args.inputFile) {
    if (!existsSync(args.inputFile)) {
      console.error(`Error: Input file not found: ${args.inputFile}`);
      process.exit(1);
    }

    console.log(`Loading policies from ${args.inputFile}...\n`);

    try {
      const content = readFileSync(args.inputFile, 'utf-8');
      const data = JSON.parse(content);

      // Handle different input formats
      if (Array.isArray(data)) {
        // Direct array of policies
        input = { policies: data };
      } else if (data.policies) {
        // Structured input
        input = {
          policies: data.policies,
          namedLocations: data.namedLocations || [],
          emergencyAccounts: data.emergencyAccounts || [],
        };
      } else if (data.value) {
        // Graph API response format
        input = { policies: data.value };
      } else {
        console.error('Error: Unrecognized input format');
        process.exit(1);
      }

      console.log(`  Loaded ${input.policies.length} policies\n`);
    } catch (error) {
      console.error('Error reading input file:', error);
      process.exit(1);
    }
  } else {
    console.error('Error: No input specified. Use --input <file> or --live');
    console.log('Run with --help for usage information.\n');
    process.exit(1);
  }

  // Run analysis
  console.log('Running security analysis...\n');
  const result = runAnalysis(input);

  // Display summary
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('                    ANALYSIS SUMMARY');
  console.log('═══════════════════════════════════════════════════════════════\n');

  console.log(`  Security Score: ${result.summary.securityScore}/100`);
  console.log(`  Total Policies: ${result.totalPolicies}`);
  console.log(`    - Enabled: ${result.enabledPolicies}`);
  console.log(`    - Report-Only: ${result.reportOnlyPolicies}`);
  console.log(`    - Disabled: ${result.disabledPolicies}`);
  console.log('');
  console.log(`  Findings: ${result.findings.length}`);
  console.log(`    🔴 Critical: ${result.summary.criticalCount}`);
  console.log(`    🟠 High:     ${result.summary.highCount}`);
  console.log(`    🟡 Medium:   ${result.summary.mediumCount}`);
  console.log(`    🔵 Low:      ${result.summary.lowCount}`);
  console.log(`    ⚪ Info:     ${result.summary.infoCount}`);
  console.log('');
  console.log('  Security Coverage:');

  const coverage = result.summary.coverageMetrics;
  console.log(`    ${coverage.mfaEnforced ? '✅' : '❌'} MFA Enforcement`);
  console.log(`    ${coverage.legacyAuthBlocked ? '✅' : '❌'} Legacy Auth Blocked`);
  console.log(`    ${coverage.adminsMfaRequired ? '✅' : '❌'} Admin MFA Required`);
  console.log(`    ${coverage.riskPoliciesConfigured ? '✅' : '❌'} Risk Policies`);
  console.log(`    ${coverage.deviceComplianceRequired ? '✅' : '❌'} Device Compliance`);
  console.log(`    ${coverage.guestAccessControlled ? '✅' : '❌'} Guest Access Controlled`);

  console.log('\n═══════════════════════════════════════════════════════════════\n');

  // Generate reports
  const outputDir = args.outputDir || './reports';
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);

  // Ensure output directory exists
  try {
    await Bun.write(`${outputDir}/.keep`, '');
  } catch {
    // Directory creation via write
  }

  const formats = args.format === 'all' ? ['html', 'json', 'markdown'] : [args.format];

  for (const format of formats) {
    let content: string;
    let filename: string;

    switch (format) {
      case 'html':
        content = generateHtmlReport(result, args.tenantName);
        filename = `ca-analysis-${timestamp}.html`;
        break;
      case 'json':
        content = generateJsonReport(result);
        filename = `ca-analysis-${timestamp}.json`;
        break;
      case 'markdown':
        content = generateMarkdownReport(result, args.tenantName);
        filename = `ca-analysis-${timestamp}.md`;
        break;
      default:
        continue;
    }

    const filepath = join(outputDir, filename);
    writeFileSync(filepath, content, 'utf-8');
    console.log(`📄 Generated: ${filepath}`);
  }

  console.log('\nAnalysis complete.\n');

  // Exit with error code if critical findings
  if (result.summary.criticalCount > 0) {
    process.exit(1);
  }
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
