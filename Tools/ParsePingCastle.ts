#!/usr/bin/env bun
// PingCastle Report Parser
// Extracts security findings from PingCastle XML/HTML reports

import { readFileSync, existsSync } from 'fs';

interface Finding {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  category: string;
  title: string;
  description: string;
  remediation: string;
  impact: string;
}

interface PingCastleRule {
  id: string;
  category: string;
  riskModel: string;
  rationale: string;
  technicalExplanation: string;
  solution: string;
  documentation: string;
  points: number;
}

function mapPingCastleSeverity(points: number): Finding['severity'] {
  if (points >= 50) return 'CRITICAL';
  if (points >= 30) return 'HIGH';
  if (points >= 15) return 'MEDIUM';
  if (points >= 5) return 'LOW';
  return 'INFO';
}

function parseXMLReport(content: string): Finding[] {
  const findings: Finding[] = [];

  // Extract risk rules from XML
  // PingCastle XML format: <RiskRule><Points>XX</Points><Category>YY</Category>...
  const ruleMatches = content.matchAll(
    /<RiskRule>[\s\S]*?<RuleId>(.*?)<\/RuleId>[\s\S]*?<Points>(\d+)<\/Points>[\s\S]*?<Category>(.*?)<\/Category>[\s\S]*?<Model>(.*?)<\/Model>[\s\S]*?<Rationale>(.*?)<\/Rationale>[\s\S]*?<TechnicalExplanation>(.*?)<\/TechnicalExplanation>[\s\S]*?<Solution>(.*?)<\/Solution>[\s\S]*?<\/RiskRule>/g
  );

  for (const match of ruleMatches) {
    const [, ruleId, points, category, model, rationale, technicalExplanation, solution] = match;

    const pointsNum = parseInt(points);
    const severity = mapPingCastleSeverity(pointsNum);

    findings.push({
      severity,
      category: category || 'General',
      title: `${ruleId}: ${rationale}`,
      description: technicalExplanation || rationale,
      impact: `PingCastle Risk Score: ${pointsNum} points. ${model}`,
      remediation: solution || 'See PingCastle documentation for detailed remediation steps.',
    });
  }

  return findings;
}

function parseHTMLReport(content: string): Finding[] {
  const findings: Finding[] = [];

  // HTML parsing - extract from risk rules table
  // Look for patterns like: <td>ruleid</td><td>points</td><td>category</td>
  const tableRowMatches = content.matchAll(
    /<tr[^>]*>[\s\S]*?<td[^>]*>\s*([A-Z]-[A-Z0-9-]+)\s*<\/td>[\s\S]*?<td[^>]*>\s*(\d+)\s*<\/td>[\s\S]*?<td[^>]*>\s*([^<]+)<\/td>[\s\S]*?<td[^>]*>\s*([^<]+)<\/td>/g
  );

  for (const match of tableRowMatches) {
    const [, ruleId, points, category, description] = match;

    const pointsNum = parseInt(points);
    if (isNaN(pointsNum)) continue;

    const severity = mapPingCastleSeverity(pointsNum);

    findings.push({
      severity,
      category: category?.trim() || 'General',
      title: `${ruleId}: ${description}`,
      description: description || 'See PingCastle report for details',
      impact: `PingCastle Risk Score: ${pointsNum} points`,
      remediation: 'Refer to PingCastle documentation for remediation guidance',
    });
  }

  return findings;
}

function extractOverallScore(content: string): number | null {
  // Try to extract overall risk score
  const scoreMatch = content.match(/<GlobalScore>(\d+)<\/GlobalScore>/) ||
                     content.match(/Global Score[:\s]+(\d+)/i) ||
                     content.match(/Total Risk[:\s]+(\d+)/i);

  if (scoreMatch) {
    return parseInt(scoreMatch[1]);
  }

  return null;
}

function extractDomainInfo(content: string): { domain?: string; assessmentDate?: string } {
  const domainMatch = content.match(/<DomainFQDN>(.*?)<\/DomainFQDN>/) ||
                     content.match(/Domain[:\s]+([a-zA-Z0-9.-]+)/);

  const dateMatch = content.match(/<GenerationDate>(.*?)<\/GenerationDate>/) ||
                   content.match(/Report Date[:\s]+([\d\/-]+)/);

  return {
    domain: domainMatch ? domainMatch[1] : undefined,
    assessmentDate: dateMatch ? dateMatch[1] : undefined,
  };
}

// Main execution
try {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.error('Usage: bun run ParsePingCastle.ts <pingcastle-report.xml|html>');
    console.error('\nGenerate PingCastle report:');
    console.error('  PingCastle.exe --healthcheck --server domain.com');
    console.error('\nSupports both XML and HTML report formats');
    process.exit(1);
  }

  const reportFile = args[0];

  if (!existsSync(reportFile)) {
    console.error(`Error: Report file not found: ${reportFile}`);
    process.exit(1);
  }

  console.log('\n🏰 Parsing PingCastle Report...\n');

  const content = readFileSync(reportFile, 'utf-8');

  // Detect format
  const isXML = content.includes('<?xml') || content.includes('<HealthcheckData');
  const isHTML = content.includes('<html') || content.includes('<!DOCTYPE html');

  let findings: Finding[] = [];

  if (isXML) {
    console.log('Detected XML format');
    findings = parseXMLReport(content);
  } else if (isHTML) {
    console.log('Detected HTML format');
    findings = parseHTMLReport(content);
  } else {
    console.error('Error: Unable to detect report format (expected XML or HTML)');
    process.exit(1);
  }

  // Extract metadata
  const info = extractDomainInfo(content);
  const overallScore = extractOverallScore(content);

  if (info.domain) {
    console.log(`Domain: ${info.domain}`);
  }
  if (info.assessmentDate) {
    console.log(`Assessment Date: ${info.assessmentDate}`);
  }
  if (overallScore !== null) {
    console.log(`Overall Risk Score: ${overallScore}/100`);
  }

  console.log(`\n✓ Parsed ${findings.length} risk rules\n`);

  // Output findings in assessment tool format
  console.log('═══════════════════════════════════════════════════════════');
  console.log('   PINGCASTLE ANALYSIS');
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

  // Sort by severity
  const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

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
    console.log('');
  });

  console.log('═══════════════════════════════════════════════════════════\n');

  if (overallScore !== null) {
    console.log(`📊 PingCastle Overall Risk Score: ${overallScore}/100`);
    if (overallScore >= 75) {
      console.log('   🔴 HIGH RISK - Immediate attention required');
    } else if (overallScore >= 50) {
      console.log('   🟠 MEDIUM RISK - Significant issues to address');
    } else if (overallScore >= 25) {
      console.log('   🟡 LOW-MEDIUM RISK - Some improvements needed');
    } else {
      console.log('   🟢 LOW RISK - Good security posture');
    }
    console.log('');
  }

  // Exit with appropriate code
  const hasCritical = findings.some(f => f.severity === 'CRITICAL');
  process.exit(hasCritical ? 1 : 0);
} catch (error) {
  console.error('Error:', error);
  process.exit(1);
}
