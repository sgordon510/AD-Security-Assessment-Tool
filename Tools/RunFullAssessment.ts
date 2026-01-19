#!/usr/bin/env bun
// Master Security Assessment Orchestration Script
// Runs all assessment tools and generates comprehensive executive report

import { existsSync, mkdirSync, writeFileSync } from 'fs';
import { join } from 'path';
import { spawnSync } from 'child_process';

interface AssessmentConfig {
  orgName: string;
  outputDir: string;
  adConfigFile?: string;
  identityDataFile?: string;
  azureADDataFile?: string;
  bloodhoundDir?: string;
  pingCastleReport?: string;
}

function runCommand(command: string, args: string[], description: string): { success: boolean; output: string } {
  console.log(`\n▶️  ${description}...`);

  const result = spawnSync(command, args, {
    encoding: 'utf-8',
    maxBuffer: 10 * 1024 * 1024,  // 10MB buffer
  });

  if (result.error) {
    console.error(`   ❌ Error: ${result.error.message}`);
    return { success: false, output: '' };
  }

  const output = result.stdout + result.stderr;

  if (result.status === 0 || result.status === 1) {  // Exit code 1 is expected for findings
    console.log(`   ✓ Complete`);
    return { success: true, output };
  } else {
    console.error(`   ❌ Failed with exit code ${result.status}`);
    return { success: false, output };
  }
}

function parseArguments(): AssessmentConfig | null {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    console.log(`
╔═══════════════════════════════════════════════════════════════════╗
║         Full AD Security Assessment - Master Script               ║
╚═══════════════════════════════════════════════════════════════════╝

Usage: bun run RunFullAssessment.ts --org "Org Name" --output ./reports [options]

Required:
  --org, -o <name>          Organization name for reports
  --output, -d <dir>        Output directory for all reports

AD/On-Prem Assessment (optional, run what you have):
  --ad-config <file>        AD configuration JSON (for AssessADMisconfigs)
  --identity <file>         Identity data JSON (for AnalyzePrivileges)
  --bloodhound <dir>        BloodHound data directory

Azure AD Assessment (optional):
  --azure <file>            Azure AD data JSON (for AuditAzureAD)

Third-Party Tools (optional):
  --pingcastle <file>       PingCastle XML/HTML report

Examples:

  # Full assessment with all data sources
  bun run RunFullAssessment.ts \\
    --org "Acme Corp" \\
    --output ~/reports/2026-01 \\
    --ad-config /tmp/ad-config.json \\
    --identity /tmp/identity-data.json \\
    --azure /tmp/azure-ad-data.json \\
    --bloodhound /tmp/bloodhound \\
    --pingcastle /tmp/pingcastle-report.xml

  # AD-only assessment
  bun run RunFullAssessment.ts \\
    --org "Acme Corp" \\
    --output ~/reports/2026-01 \\
    --ad-config /tmp/ad-config.json \\
    --bloodhound /tmp/bloodhound

  # Azure AD only
  bun run RunFullAssessment.ts \\
    --org "Acme Corp" \\
    --output ~/reports/2026-01 \\
    --azure /tmp/azure-ad-data.json

Output:
  - Individual assessment reports (report-*.txt)
  - Executive dashboard (executive-report.html)
  - Summary metrics (summary.json)
`);
    return null;
  }

  const config: AssessmentConfig = {
    orgName: '',
    outputDir: '',
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    const next = args[i + 1];

    switch (arg) {
      case '--org':
      case '-o':
        config.orgName = next;
        i++;
        break;
      case '--output':
      case '-d':
        config.outputDir = next;
        i++;
        break;
      case '--ad-config':
        config.adConfigFile = next;
        i++;
        break;
      case '--identity':
        config.identityDataFile = next;
        i++;
        break;
      case '--azure':
        config.azureADDataFile = next;
        i++;
        break;
      case '--bloodhound':
        config.bloodhoundDir = next;
        i++;
        break;
      case '--pingcastle':
        config.pingCastleReport = next;
        i++;
        break;
    }
  }

  // Validate required fields
  if (!config.orgName) {
    console.error('Error: --org is required');
    return null;
  }

  if (!config.outputDir) {
    console.error('Error: --output is required');
    return null;
  }

  // Check that at least one data source is provided
  const hasDataSource =
    config.adConfigFile ||
    config.identityDataFile ||
    config.azureADDataFile ||
    config.bloodhoundDir ||
    config.pingCastleReport;

  if (!hasDataSource) {
    console.error('Error: At least one data source must be provided');
    console.error('Use --ad-config, --identity, --azure, --bloodhound, or --pingcastle');
    return null;
  }

  return config;
}

// Main execution
try {
  const config = parseArguments();

  if (!config) {
    process.exit(1);
  }

  console.log(`
╔═══════════════════════════════════════════════════════════════════╗
║         Full AD Security Assessment                               ║
║         Organization: ${config.orgName.padEnd(47)}║
╚═══════════════════════════════════════════════════════════════════╝
`);

  // Create output directory
  if (!existsSync(config.outputDir)) {
    mkdirSync(config.outputDir, { recursive: true });
    console.log(`✓ Created output directory: ${config.outputDir}\n`);
  }

  const toolsDir = join(import.meta.dir);
  const reports: string[] = [];
  let assessmentCount = 0;

  // === AD CONFIGURATION ASSESSMENT ===
  if (config.adConfigFile) {
    if (!existsSync(config.adConfigFile)) {
      console.error(`⚠️  AD config file not found: ${config.adConfigFile}`);
    } else {
      const result = runCommand(
        'bun',
        ['run', join(toolsDir, 'AssessADMisconfigs.ts'), config.adConfigFile],
        'Running AD Configuration Assessment'
      );

      if (result.success) {
        const reportPath = join(config.outputDir, 'report-ad-misconfigs.txt');
        writeFileSync(reportPath, result.output);
        reports.push(reportPath);
        assessmentCount++;
      }
    }
  }

  // === PRIVILEGE ANALYSIS ===
  if (config.identityDataFile) {
    if (!existsSync(config.identityDataFile)) {
      console.error(`⚠️  Identity data file not found: ${config.identityDataFile}`);
    } else {
      const result = runCommand(
        'bun',
        ['run', join(toolsDir, 'AnalyzePrivileges.ts'), config.identityDataFile],
        'Running Privilege & Access Analysis'
      );

      if (result.success) {
        const reportPath = join(config.outputDir, 'report-privileges.txt');
        writeFileSync(reportPath, result.output);
        reports.push(reportPath);
        assessmentCount++;
      }
    }
  }

  // === AZURE AD ASSESSMENT ===
  if (config.azureADDataFile) {
    if (!existsSync(config.azureADDataFile)) {
      console.error(`⚠️  Azure AD data file not found: ${config.azureADDataFile}`);
    } else {
      const result = runCommand(
        'bun',
        ['run', join(toolsDir, 'AuditAzureAD.ts'), config.azureADDataFile],
        'Running Azure AD Security Assessment'
      );

      if (result.success) {
        const reportPath = join(config.outputDir, 'report-azure-ad.txt');
        writeFileSync(reportPath, result.output);
        reports.push(reportPath);
        assessmentCount++;
      }
    }
  }

  // === BLOODHOUND ANALYSIS ===
  if (config.bloodhoundDir) {
    if (!existsSync(config.bloodhoundDir)) {
      console.error(`⚠️  BloodHound directory not found: ${config.bloodhoundDir}`);
    } else {
      const result = runCommand(
        'bun',
        ['run', join(toolsDir, 'ParseBloodHound.ts'), config.bloodhoundDir],
        'Parsing BloodHound Data'
      );

      if (result.success) {
        const reportPath = join(config.outputDir, 'report-bloodhound.txt');
        writeFileSync(reportPath, result.output);
        reports.push(reportPath);
        assessmentCount++;
      }
    }
  }

  // === PINGCASTLE ANALYSIS ===
  if (config.pingCastleReport) {
    if (!existsSync(config.pingCastleReport)) {
      console.error(`⚠️  PingCastle report not found: ${config.pingCastleReport}`);
    } else {
      const result = runCommand(
        'bun',
        ['run', join(toolsDir, 'ParsePingCastle.ts'), config.pingCastleReport],
        'Parsing PingCastle Report'
      );

      if (result.success) {
        const reportPath = join(config.outputDir, 'report-pingcastle.txt');
        writeFileSync(reportPath, result.output);
        reports.push(reportPath);
        assessmentCount++;
      }
    }
  }

  if (assessmentCount === 0) {
    console.error('\n❌ No assessments completed successfully');
    process.exit(1);
  }

  console.log(`\n✅ Completed ${assessmentCount} assessments`);

  // === GENERATE EXECUTIVE REPORT ===
  console.log('\n' + '═'.repeat(67));
  const result = runCommand(
    'bun',
    [
      'run',
      join(toolsDir, 'GenerateExecutiveReport.ts'),
      config.outputDir,
      config.orgName,
      join(config.outputDir, 'executive-report.html'),
    ],
    'Generating Executive Dashboard'
  );

  if (!result.success) {
    console.error('\n⚠️  Executive report generation failed');
  }

  // === SUMMARY ===
  console.log('\n' + '═'.repeat(67));
  console.log('Assessment Complete!\n');
  console.log('Output Directory:', config.outputDir);
  console.log('\nGenerated Reports:');
  console.log('   • executive-report.html  (Open in browser for executive summary)');
  reports.forEach(r => {
    console.log(`   • ${r.split('/').pop()}  (Technical details)`);
  });

  console.log('\nView Executive Report:');
  console.log(`   file://${join(config.outputDir, 'executive-report.html')}`);

  console.log('\nNext Steps:');
  console.log('   1. Review executive dashboard with leadership');
  console.log('   2. Prioritize CRITICAL and HIGH findings');
  console.log('   3. Assign remediation owners');
  console.log('   4. Track progress for next monthly assessment');

  console.log('\n' + '═'.repeat(67) + '\n');

  process.exit(0);
} catch (error) {
  console.error('\n❌ Fatal Error:', error);
  process.exit(1);
}
