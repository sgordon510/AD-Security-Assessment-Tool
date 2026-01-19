#!/usr/bin/env bun
// Executive Report Generator
// Converts assessment findings into executive-friendly HTML dashboard

import { readFileSync, writeFileSync, readdirSync, existsSync } from 'fs';
import { join, basename } from 'path';

interface Finding {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  category: string;
  title: string;
  description: string;
  remediation?: string;
  impact?: string;
  account?: string;
  issue?: string;
}

interface AssessmentData {
  date: string;
  type: 'AD_Misconfigs' | 'Privilege_Analysis' | 'Azure_AD';
  findings: Finding[];
}

interface ExecutiveMetrics {
  overallRiskScore: number;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  topRisks: Finding[];
  categoryBreakdown: Record<string, number>;
  trendData?: {
    previousMonth?: {
      date: string;
      totalFindings: number;
      criticalCount: number;
    };
    change?: string;
  };
}

function calculateRiskScore(findings: Finding[]): number {
  // Risk scoring: CRITICAL=10, HIGH=5, MEDIUM=2, LOW=1, INFO=0
  const weights = { CRITICAL: 10, HIGH: 5, MEDIUM: 2, LOW: 1, INFO: 0 };

  const totalRisk = findings.reduce((sum, f) => sum + weights[f.severity], 0);
  const maxPossibleRisk = findings.length * 10;

  // Return score out of 100 (inverted - 100 is perfect, 0 is terrible)
  return maxPossibleRisk > 0 ? Math.round((1 - totalRisk / maxPossibleRisk) * 100) : 100;
}

function generateMetrics(assessments: AssessmentData[]): ExecutiveMetrics {
  const allFindings = assessments.flatMap(a => a.findings);

  const criticalCount = allFindings.filter(f => f.severity === 'CRITICAL').length;
  const highCount = allFindings.filter(f => f.severity === 'HIGH').length;
  const mediumCount = allFindings.filter(f => f.severity === 'MEDIUM').length;
  const lowCount = allFindings.filter(f => f.severity === 'LOW').length;
  const infoCount = allFindings.filter(f => f.severity === 'INFO').length;

  // Category breakdown
  const categoryBreakdown: Record<string, number> = {};
  allFindings.forEach(f => {
    categoryBreakdown[f.category] = (categoryBreakdown[f.category] || 0) + 1;
  });

  // Top 5 critical/high risks
  const topRisks = allFindings
    .filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH')
    .slice(0, 5);

  return {
    overallRiskScore: calculateRiskScore(allFindings),
    totalFindings: allFindings.length,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    infoCount,
    topRisks,
    categoryBreakdown,
  };
}

function generateHTML(metrics: ExecutiveMetrics, assessments: AssessmentData[], orgName: string): string {
  const latestDate = assessments[0]?.date || new Date().toISOString().split('T')[0];

  // Risk score color
  const riskScoreColor =
    metrics.overallRiskScore >= 80 ? '#10b981' :  // Green
    metrics.overallRiskScore >= 60 ? '#f59e0b' :  // Yellow
    metrics.overallRiskScore >= 40 ? '#f97316' :  // Orange
    '#ef4444';  // Red

  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Executive Report - ${orgName}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #1f2937;
            background: #f3f4f6;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            border-radius: 8px;
        }

        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 8px 8px 0 0;
        }

        .header h1 {
            font-size: 32px;
            margin-bottom: 10px;
        }

        .header .subtitle {
            opacity: 0.9;
            font-size: 16px;
        }

        .header .date {
            margin-top: 15px;
            font-size: 14px;
            opacity: 0.8;
        }

        .content {
            padding: 40px;
        }

        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }

        .metric-card {
            background: #f9fafb;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            padding: 24px;
            text-align: center;
        }

        .metric-card.risk-score {
            background: linear-gradient(135deg, ${riskScoreColor}15 0%, ${riskScoreColor}05 100%);
            border-color: ${riskScoreColor}40;
        }

        .metric-value {
            font-size: 48px;
            font-weight: bold;
            color: #1f2937;
            margin-bottom: 8px;
        }

        .metric-card.risk-score .metric-value {
            color: ${riskScoreColor};
        }

        .metric-label {
            font-size: 14px;
            color: #6b7280;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .severity-breakdown {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 15px;
            margin-bottom: 40px;
        }

        .severity-item {
            background: white;
            border: 2px solid #e5e7eb;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }

        .severity-item.critical { border-color: #ef4444; }
        .severity-item.high { border-color: #f97316; }
        .severity-item.medium { border-color: #f59e0b; }
        .severity-item.low { border-color: #3b82f6; }
        .severity-item.info { border-color: #6b7280; }

        .severity-count {
            font-size: 36px;
            font-weight: bold;
            margin-bottom: 8px;
        }

        .severity-item.critical .severity-count { color: #ef4444; }
        .severity-item.high .severity-count { color: #f97316; }
        .severity-item.medium .severity-count { color: #f59e0b; }
        .severity-item.low .severity-count { color: #3b82f6; }
        .severity-item.info .severity-count { color: #6b7280; }

        .severity-label {
            font-size: 12px;
            text-transform: uppercase;
            color: #6b7280;
            letter-spacing: 0.5px;
        }

        .section {
            margin-bottom: 40px;
        }

        .section-title {
            font-size: 24px;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e5e7eb;
            color: #1f2937;
        }

        .finding-card {
            background: #f9fafb;
            border-left: 4px solid #e5e7eb;
            border-radius: 4px;
            padding: 20px;
            margin-bottom: 15px;
        }

        .finding-card.critical { border-left-color: #ef4444; }
        .finding-card.high { border-left-color: #f97316; }
        .finding-card.medium { border-left-color: #f59e0b; }

        .finding-header {
            display: flex;
            align-items: center;
            margin-bottom: 10px;
        }

        .severity-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-right: 12px;
        }

        .severity-badge.critical {
            background: #ef4444;
            color: white;
        }

        .severity-badge.high {
            background: #f97316;
            color: white;
        }

        .severity-badge.medium {
            background: #f59e0b;
            color: white;
        }

        .finding-title {
            font-size: 18px;
            font-weight: 600;
            color: #1f2937;
        }

        .finding-description {
            color: #4b5563;
            margin-bottom: 10px;
            line-height: 1.6;
        }

        .finding-impact {
            background: white;
            border-radius: 4px;
            padding: 12px;
            margin-top: 10px;
            font-size: 14px;
        }

        .finding-impact strong {
            color: #7c3aed;
        }

        .category-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 40px;
        }

        .category-item {
            background: #f9fafb;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            padding: 16px;
        }

        .category-name {
            font-size: 14px;
            color: #6b7280;
            margin-bottom: 8px;
        }

        .category-count {
            font-size: 24px;
            font-weight: bold;
            color: #1f2937;
        }

        .summary-box {
            background: #eff6ff;
            border: 1px solid #bfdbfe;
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 30px;
        }

        .summary-box h3 {
            color: #1e40af;
            margin-bottom: 15px;
        }

        .summary-box ul {
            list-style: none;
            padding-left: 0;
        }

        .summary-box li {
            padding: 8px 0;
            color: #1e40af;
        }

        .summary-box li::before {
            content: "→ ";
            font-weight: bold;
            margin-right: 8px;
        }

        .footer {
            background: #f9fafb;
            padding: 24px 40px;
            border-radius: 0 0 8px 8px;
            text-align: center;
            color: #6b7280;
            font-size: 14px;
        }

        @media print {
            body {
                background: white;
                padding: 0;
            }

            .container {
                box-shadow: none;
            }

            .finding-card {
                page-break-inside: avoid;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Assessment Report</h1>
            <div class="subtitle">${orgName} - Identity Infrastructure Security Posture</div>
            <div class="date">Assessment Date: ${latestDate}</div>
        </div>

        <div class="content">
            <!-- Executive Summary -->
            <div class="summary-box">
                <h3>Executive Summary</h3>
                <ul>
                    <li>Overall security posture score: <strong>${metrics.overallRiskScore}/100</strong></li>
                    <li>Total findings identified: <strong>${metrics.totalFindings}</strong></li>
                    <li>Critical issues requiring immediate attention: <strong>${metrics.criticalCount}</strong></li>
                    <li>High-priority items for remediation: <strong>${metrics.highCount}</strong></li>
                    ${metrics.criticalCount > 0 ? '<li><strong>Immediate action required on critical findings</strong></li>' : ''}
                </ul>
            </div>

            <!-- Key Metrics -->
            <div class="metrics-grid">
                <div class="metric-card risk-score">
                    <div class="metric-value">${metrics.overallRiskScore}</div>
                    <div class="metric-label">Security Score</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">${metrics.totalFindings}</div>
                    <div class="metric-label">Total Findings</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">${metrics.criticalCount + metrics.highCount}</div>
                    <div class="metric-label">Priority Items</div>
                </div>
            </div>

            <!-- Severity Breakdown -->
            <div class="section">
                <h2 class="section-title">Finding Severity Distribution</h2>
                <div class="severity-breakdown">
                    <div class="severity-item critical">
                        <div class="severity-count">${metrics.criticalCount}</div>
                        <div class="severity-label">Critical</div>
                    </div>
                    <div class="severity-item high">
                        <div class="severity-count">${metrics.highCount}</div>
                        <div class="severity-label">High</div>
                    </div>
                    <div class="severity-item medium">
                        <div class="severity-count">${metrics.mediumCount}</div>
                        <div class="severity-label">Medium</div>
                    </div>
                    <div class="severity-item low">
                        <div class="severity-count">${metrics.lowCount}</div>
                        <div class="severity-label">Low</div>
                    </div>
                    <div class="severity-item info">
                        <div class="severity-count">${metrics.infoCount}</div>
                        <div class="severity-label">Info</div>
                    </div>
                </div>
            </div>

            <!-- Risk Categories -->
            <div class="section">
                <h2 class="section-title">Risk Categories</h2>
                <div class="category-grid">
                    ${Object.entries(metrics.categoryBreakdown)
                      .sort((a, b) => b[1] - a[1])
                      .map(([category, count]) => `
                        <div class="category-item">
                            <div class="category-name">${category}</div>
                            <div class="category-count">${count}</div>
                        </div>
                    `).join('')}
                </div>
            </div>

            <!-- Top Priority Findings -->
            <div class="section">
                <h2 class="section-title">Top Priority Findings (Action Required)</h2>
                ${metrics.topRisks.length > 0 ? metrics.topRisks.map((finding, index) => `
                    <div class="finding-card ${finding.severity.toLowerCase()}">
                        <div class="finding-header">
                            <span class="severity-badge ${finding.severity.toLowerCase()}">${finding.severity}</span>
                            <span class="finding-title">${index + 1}. ${finding.title}</span>
                        </div>
                        <div class="finding-description">
                            ${finding.description || finding.issue || ''}
                        </div>
                        ${finding.impact ? `
                            <div class="finding-impact">
                                <strong>Impact:</strong> ${finding.impact}
                            </div>
                        ` : ''}
                        ${finding.remediation ? `
                            <div class="finding-impact">
                                <strong>Remediation:</strong> ${finding.remediation}
                            </div>
                        ` : ''}
                    </div>
                `).join('') : '<p>No critical or high-priority findings detected.</p>'}
            </div>

            <!-- Assessment Coverage -->
            <div class="section">
                <h2 class="section-title">Assessment Coverage</h2>
                <div class="category-grid">
                    ${assessments.map(a => `
                        <div class="category-item">
                            <div class="category-name">${a.type.replace(/_/g, ' ')}</div>
                            <div class="category-count">${a.findings.length}</div>
                        </div>
                    `).join('')}
                </div>
            </div>

            <!-- Recommendations -->
            <div class="summary-box">
                <h3>Recommended Next Steps</h3>
                <ul>
                    ${metrics.criticalCount > 0 ? '<li>Address all CRITICAL findings within 24-48 hours</li>' : ''}
                    ${metrics.highCount > 0 ? '<li>Plan remediation for HIGH severity items within 1-2 weeks</li>' : ''}
                    <li>Review detailed technical findings in assessment reports</li>
                    <li>Schedule follow-up assessment after remediation</li>
                    <li>Consider implementing continuous monitoring for key security controls</li>
                </ul>
            </div>
        </div>

        <div class="footer">
            Generated by AD Security Assessment Tool | ${new Date().toISOString().split('T')[0]}<br>
            This report is confidential and intended for authorized personnel only.
        </div>
    </div>
</body>
</html>`;
}

// Parse assessment output text to extract findings
function parseAssessmentOutput(text: string, type: string): Finding[] {
  const findings: Finding[] = [];
  const lines = text.split('\n');

  let currentFinding: Partial<Finding> | null = null;
  let lastField: string = '';

  for (const line of lines) {
    // Match severity headers like: [CRITICAL] Title
    const headerMatch = line.match(/^\[(\w+)\]\s+(.+)$/);
    const hasEmoji = /[🔴🟠🟡🔵⚪]/.test(line);

    if (headerMatch && hasEmoji && !line.startsWith('   ')) {
      // Save previous finding
      if (currentFinding && currentFinding.severity && currentFinding.title) {
        findings.push(currentFinding as Finding);
      }

      // Start new finding
      currentFinding = {
        severity: headerMatch[1] as Finding['severity'],
        title: headerMatch[2],
        category: '',
        description: '',
      };
      lastField = '';
      continue;
    }

    // Parse field lines
    if (currentFinding && line.trim()) {
      if (line.startsWith('   Category:')) {
        currentFinding.category = line.replace('   Category:', '').trim();
        lastField = 'category';
      } else if (line.startsWith('   Account:')) {
        currentFinding.account = line.replace('   Account:', '').trim();
        lastField = 'account';
      } else if (line.startsWith('   Issue:')) {
        currentFinding.issue = line.replace('   Issue:', '').trim();
        lastField = 'issue';
      } else if (line.startsWith('   Impact:')) {
        currentFinding.impact = line.replace('   Impact:', '').trim();
        lastField = 'impact';
      } else if (line.startsWith('   Remediation:')) {
        currentFinding.remediation = line.replace('   Remediation:', '').trim();
        lastField = 'remediation';
      } else if (line.startsWith('   References:')) {
        // Skip references line
        lastField = '';
      } else if (line.startsWith('   ') && !line.includes(':') && line.trim()) {
        // Continuation line for description or other fields
        if (!lastField || lastField === 'category') {
          // This is the description (first non-field line after category)
          currentFinding.description = (currentFinding.description || '') + ' ' + line.trim();
        }
      }
    }
  }

  // Add last finding
  if (currentFinding && currentFinding.severity && currentFinding.title) {
    findings.push(currentFinding as Finding);
  }

  return findings;
}

// Main execution
try {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.error('Usage: bun run GenerateExecutiveReport.ts <assessment-reports-dir> [org-name] [output-file]');
    console.error('\nExample:');
    console.error('  bun run GenerateExecutiveReport.ts /tmp/assessment "Acme Corp" executive-report.html');
    console.error('\nExpected directory structure:');
    console.error('  /tmp/assessment/');
    console.error('    ├── report-misconfigs.txt');
    console.error('    ├── report-privileges.txt');
    console.error('    └── report-azure.txt');
    process.exit(1);
  }

  const reportsDir = args[0];
  const orgName = args[1] || 'Your Organization';
  const outputFile = args[2] || 'executive-report.html';

  if (!existsSync(reportsDir)) {
    console.error(`Error: Directory not found: ${reportsDir}`);
    process.exit(1);
  }

  console.log('\nGenerating Executive Report...\n');

  // Load assessment reports
  const assessments: AssessmentData[] = [];
  const reportFiles = readdirSync(reportsDir).filter(f => f.endsWith('.txt'));

  for (const file of reportFiles) {
    const filePath = join(reportsDir, file);
    const content = readFileSync(filePath, 'utf-8');

    let type: AssessmentData['type'];
    if (file.includes('misconfig')) {
      type = 'AD_Misconfigs';
    } else if (file.includes('privilege')) {
      type = 'Privilege_Analysis';
    } else if (file.includes('azure')) {
      type = 'Azure_AD';
    } else {
      continue;
    }

    const findings = parseAssessmentOutput(content, type);

    assessments.push({
      date: new Date().toISOString().split('T')[0],
      type,
      findings,
    });

    console.log(`Loaded ${findings.length} findings from ${file}`);
  }

  if (assessments.length === 0) {
    console.error('Error: No assessment reports found in directory');
    process.exit(1);
  }

  // Generate metrics
  const metrics = generateMetrics(assessments);

  console.log('\nAssessment Metrics:');
  console.log(`   Security Score: ${metrics.overallRiskScore}/100`);
  console.log(`   Total Findings: ${metrics.totalFindings}`);
  console.log(`   Critical: ${metrics.criticalCount}`);
  console.log(`   High: ${metrics.highCount}`);
  console.log(`   Medium: ${metrics.mediumCount}`);
  console.log(`   Low: ${metrics.lowCount}`);

  // Generate HTML
  const html = generateHTML(metrics, assessments, orgName);

  // Write to file
  writeFileSync(outputFile, html, 'utf-8');

  console.log(`\nExecutive report generated: ${outputFile}`);
  console.log(`\nOpen in browser:`);
  console.log(`   file://${join(process.cwd(), outputFile)}`);

  process.exit(0);
} catch (error) {
  console.error('Error:', error);
  process.exit(1);
}
