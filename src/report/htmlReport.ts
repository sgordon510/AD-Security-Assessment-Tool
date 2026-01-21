// HTML Report Generator for Azure CA Policy Analyzer
// Generates executive-friendly HTML dashboard with findings

import type { Finding, AnalysisResult, Severity } from '../types';

function getSeverityColor(severity: Severity): string {
  switch (severity) {
    case 'CRITICAL':
      return '#dc2626';
    case 'HIGH':
      return '#ea580c';
    case 'MEDIUM':
      return '#d97706';
    case 'LOW':
      return '#2563eb';
    case 'INFO':
      return '#6b7280';
    default:
      return '#6b7280';
  }
}

function getSeverityBgColor(severity: Severity): string {
  switch (severity) {
    case 'CRITICAL':
      return '#fef2f2';
    case 'HIGH':
      return '#fff7ed';
    case 'MEDIUM':
      return '#fffbeb';
    case 'LOW':
      return '#eff6ff';
    case 'INFO':
      return '#f9fafb';
    default:
      return '#f9fafb';
  }
}

function getScoreColor(score: number): string {
  if (score >= 80) return '#10b981';
  if (score >= 60) return '#f59e0b';
  if (score >= 40) return '#f97316';
  return '#ef4444';
}

function getScoreGrade(score: number): string {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

export function generateHtmlReport(
  result: AnalysisResult,
  tenantName: string = 'Your Organization'
): string {
  const { findings, summary } = result;
  const scoreColor = getScoreColor(summary.securityScore);
  const grade = getScoreGrade(summary.securityScore);

  // Group findings by category
  const findingsByCategory: Record<string, Finding[]> = {};
  for (const finding of findings) {
    if (!findingsByCategory[finding.category]) {
      findingsByCategory[finding.category] = [];
    }
    findingsByCategory[finding.category].push(finding);
  }

  // Sort categories by severity of their findings
  const severityOrder: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 1,
    MEDIUM: 2,
    LOW: 3,
    INFO: 4,
  };

  const sortedCategories = Object.entries(findingsByCategory).sort(
    ([, a], [, b]) => {
      const aMax = Math.min(...a.map((f) => severityOrder[f.severity]));
      const bMax = Math.min(...b.map((f) => severityOrder[f.severity]));
      return aMax - bMax;
    }
  );

  // Generate coverage metrics HTML
  const coverageMetrics = summary.coverageMetrics;
  const coverageItems = [
    { label: 'MFA Enforcement', value: coverageMetrics.mfaEnforced },
    { label: 'Legacy Auth Blocked', value: coverageMetrics.legacyAuthBlocked },
    { label: 'Admin MFA Required', value: coverageMetrics.adminsMfaRequired },
    { label: 'Risk Policies', value: coverageMetrics.riskPoliciesConfigured },
    { label: 'Device Compliance', value: coverageMetrics.deviceComplianceRequired },
    { label: 'Guest Access Controlled', value: coverageMetrics.guestAccessControlled },
  ];

  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Azure CA Policy Analysis - ${escapeHtml(tenantName)}</title>
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
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }

        /* Header */
        .header {
            background: linear-gradient(135deg, #1e40af 0%, #7c3aed 100%);
            color: white;
            padding: 40px;
            border-radius: 12px;
            margin-bottom: 24px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }

        .header h1 {
            font-size: 28px;
            margin-bottom: 8px;
        }

        .header .subtitle {
            opacity: 0.9;
            font-size: 16px;
        }

        .header .meta {
            margin-top: 16px;
            font-size: 14px;
            opacity: 0.8;
        }

        /* Score Section */
        .score-section {
            display: grid;
            grid-template-columns: 200px 1fr;
            gap: 24px;
            margin-bottom: 24px;
        }

        .score-card {
            background: white;
            border-radius: 12px;
            padding: 32px;
            text-align: center;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }

        .score-value {
            font-size: 72px;
            font-weight: bold;
            color: ${scoreColor};
            line-height: 1;
        }

        .score-grade {
            font-size: 24px;
            font-weight: bold;
            color: ${scoreColor};
            margin-top: 8px;
        }

        .score-label {
            font-size: 14px;
            color: #6b7280;
            margin-top: 8px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        /* Summary Cards */
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            background: white;
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }

        .summary-item {
            text-align: center;
            padding: 16px;
            border-radius: 8px;
            background: #f9fafb;
        }

        .summary-item.critical { border-left: 4px solid #dc2626; }
        .summary-item.high { border-left: 4px solid #ea580c; }
        .summary-item.medium { border-left: 4px solid #d97706; }
        .summary-item.low { border-left: 4px solid #2563eb; }
        .summary-item.info { border-left: 4px solid #6b7280; }

        .summary-count {
            font-size: 36px;
            font-weight: bold;
        }

        .summary-item.critical .summary-count { color: #dc2626; }
        .summary-item.high .summary-count { color: #ea580c; }
        .summary-item.medium .summary-count { color: #d97706; }
        .summary-item.low .summary-count { color: #2563eb; }
        .summary-item.info .summary-count { color: #6b7280; }

        .summary-label {
            font-size: 12px;
            text-transform: uppercase;
            color: #6b7280;
            margin-top: 4px;
        }

        /* Policy Stats */
        .stats-section {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 24px;
            margin-bottom: 24px;
        }

        .stats-card {
            background: white;
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }

        .stats-card h3 {
            font-size: 16px;
            color: #374151;
            margin-bottom: 16px;
            padding-bottom: 8px;
            border-bottom: 1px solid #e5e7eb;
        }

        .stats-row {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #f3f4f6;
        }

        .stats-row:last-child {
            border-bottom: none;
        }

        .stats-label {
            color: #6b7280;
        }

        .stats-value {
            font-weight: 600;
            color: #1f2937;
        }

        /* Coverage Metrics */
        .coverage-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 12px;
        }

        .coverage-item {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 12px;
            background: #f9fafb;
            border-radius: 8px;
        }

        .coverage-icon {
            width: 24px;
            height: 24px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 14px;
        }

        .coverage-icon.pass {
            background: #dcfce7;
            color: #16a34a;
        }

        .coverage-icon.fail {
            background: #fee2e2;
            color: #dc2626;
        }

        .coverage-label {
            font-size: 13px;
            color: #374151;
        }

        /* Findings Section */
        .findings-section {
            background: white;
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }

        .findings-section h2 {
            font-size: 20px;
            margin-bottom: 20px;
            padding-bottom: 12px;
            border-bottom: 2px solid #e5e7eb;
        }

        .category-section {
            margin-bottom: 24px;
        }

        .category-header {
            font-size: 16px;
            font-weight: 600;
            color: #374151;
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .category-count {
            background: #e5e7eb;
            color: #374151;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 12px;
        }

        .finding-card {
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 12px;
            border-left: 4px solid;
        }

        .finding-card.critical {
            background: ${getSeverityBgColor('CRITICAL')};
            border-left-color: ${getSeverityColor('CRITICAL')};
        }

        .finding-card.high {
            background: ${getSeverityBgColor('HIGH')};
            border-left-color: ${getSeverityColor('HIGH')};
        }

        .finding-card.medium {
            background: ${getSeverityBgColor('MEDIUM')};
            border-left-color: ${getSeverityColor('MEDIUM')};
        }

        .finding-card.low {
            background: ${getSeverityBgColor('LOW')};
            border-left-color: ${getSeverityColor('LOW')};
        }

        .finding-card.info {
            background: ${getSeverityBgColor('INFO')};
            border-left-color: ${getSeverityColor('INFO')};
        }

        .finding-header {
            display: flex;
            align-items: flex-start;
            gap: 12px;
            margin-bottom: 8px;
        }

        .severity-badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
            text-transform: uppercase;
            color: white;
            flex-shrink: 0;
        }

        .severity-badge.critical { background: ${getSeverityColor('CRITICAL')}; }
        .severity-badge.high { background: ${getSeverityColor('HIGH')}; }
        .severity-badge.medium { background: ${getSeverityColor('MEDIUM')}; }
        .severity-badge.low { background: ${getSeverityColor('LOW')}; }
        .severity-badge.info { background: ${getSeverityColor('INFO')}; }

        .finding-title {
            font-size: 15px;
            font-weight: 600;
            color: #1f2937;
        }

        .finding-id {
            font-size: 11px;
            color: #6b7280;
            margin-left: auto;
            font-family: monospace;
        }

        .finding-description {
            color: #4b5563;
            font-size: 14px;
            margin-bottom: 12px;
            line-height: 1.5;
        }

        .finding-details {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 12px;
        }

        .finding-detail {
            background: white;
            border-radius: 6px;
            padding: 12px;
        }

        .finding-detail-label {
            font-size: 11px;
            text-transform: uppercase;
            color: #6b7280;
            margin-bottom: 4px;
        }

        .finding-detail-value {
            font-size: 13px;
            color: #1f2937;
        }

        .finding-references {
            margin-top: 12px;
            padding-top: 12px;
            border-top: 1px solid rgba(0,0,0,0.1);
        }

        .finding-references a {
            font-size: 12px;
            color: #2563eb;
            text-decoration: none;
            display: block;
            margin-top: 4px;
        }

        .finding-references a:hover {
            text-decoration: underline;
        }

        /* Footer */
        .footer {
            text-align: center;
            padding: 24px;
            color: #6b7280;
            font-size: 14px;
        }

        /* Print Styles */
        @media print {
            body {
                background: white;
            }

            .container {
                max-width: none;
                padding: 0;
            }

            .header {
                background: #1e40af !important;
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }

            .finding-card {
                break-inside: avoid;
            }
        }

        /* Responsive */
        @media (max-width: 768px) {
            .score-section {
                grid-template-columns: 1fr;
            }

            .summary-grid {
                grid-template-columns: repeat(3, 1fr);
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>Azure Conditional Access Policy Analysis</h1>
            <div class="subtitle">${escapeHtml(tenantName)}</div>
            <div class="meta">
                Analysis Date: ${result.analyzedAt} |
                Total Policies: ${result.totalPolicies} |
                Enabled: ${result.enabledPolicies} |
                Report-Only: ${result.reportOnlyPolicies}
            </div>
        </header>

        <!-- Score Section -->
        <section class="score-section">
            <div class="score-card">
                <div class="score-value">${summary.securityScore}</div>
                <div class="score-grade">Grade: ${grade}</div>
                <div class="score-label">Security Score</div>
            </div>

            <div class="summary-grid">
                <div class="summary-item critical">
                    <div class="summary-count">${summary.criticalCount}</div>
                    <div class="summary-label">Critical</div>
                </div>
                <div class="summary-item high">
                    <div class="summary-count">${summary.highCount}</div>
                    <div class="summary-label">High</div>
                </div>
                <div class="summary-item medium">
                    <div class="summary-count">${summary.mediumCount}</div>
                    <div class="summary-label">Medium</div>
                </div>
                <div class="summary-item low">
                    <div class="summary-count">${summary.lowCount}</div>
                    <div class="summary-label">Low</div>
                </div>
                <div class="summary-item info">
                    <div class="summary-count">${summary.infoCount}</div>
                    <div class="summary-label">Info</div>
                </div>
            </div>
        </section>

        <!-- Stats Section -->
        <section class="stats-section">
            <div class="stats-card">
                <h3>Policy Statistics</h3>
                <div class="stats-row">
                    <span class="stats-label">Total Policies</span>
                    <span class="stats-value">${result.totalPolicies}</span>
                </div>
                <div class="stats-row">
                    <span class="stats-label">Enabled</span>
                    <span class="stats-value">${result.enabledPolicies}</span>
                </div>
                <div class="stats-row">
                    <span class="stats-label">Report-Only</span>
                    <span class="stats-value">${result.reportOnlyPolicies}</span>
                </div>
                <div class="stats-row">
                    <span class="stats-label">Disabled</span>
                    <span class="stats-value">${result.disabledPolicies}</span>
                </div>
                <div class="stats-row">
                    <span class="stats-label">Total Findings</span>
                    <span class="stats-value">${findings.length}</span>
                </div>
            </div>

            <div class="stats-card">
                <h3>Security Coverage</h3>
                <div class="coverage-grid">
                    ${coverageItems
                      .map(
                        (item) => `
                        <div class="coverage-item">
                            <div class="coverage-icon ${item.value ? 'pass' : 'fail'}">
                                ${item.value ? '✓' : '✗'}
                            </div>
                            <span class="coverage-label">${item.label}</span>
                        </div>
                    `
                      )
                      .join('')}
                </div>
            </div>
        </section>

        <!-- Findings Section -->
        <section class="findings-section">
            <h2>Security Findings (${findings.length})</h2>

            ${
              findings.length === 0
                ? '<p>No security findings detected. Your Conditional Access policies appear to be well-configured.</p>'
                : sortedCategories
                    .map(
                      ([category, categoryFindings]) => `
                <div class="category-section">
                    <div class="category-header">
                        ${escapeHtml(category)}
                        <span class="category-count">${categoryFindings.length}</span>
                    </div>
                    ${categoryFindings
                      .sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity])
                      .map(
                        (finding) => `
                        <div class="finding-card ${finding.severity.toLowerCase()}">
                            <div class="finding-header">
                                <span class="severity-badge ${finding.severity.toLowerCase()}">${finding.severity}</span>
                                <span class="finding-title">${escapeHtml(finding.title)}</span>
                                <span class="finding-id">${finding.id}</span>
                            </div>
                            <div class="finding-description">${escapeHtml(finding.description)}</div>
                            <div class="finding-details">
                                <div class="finding-detail">
                                    <div class="finding-detail-label">Impact</div>
                                    <div class="finding-detail-value">${escapeHtml(finding.impact)}</div>
                                </div>
                                <div class="finding-detail">
                                    <div class="finding-detail-label">Remediation</div>
                                    <div class="finding-detail-value">${escapeHtml(finding.remediation)}</div>
                                </div>
                            </div>
                            ${
                              finding.affectedPolicies && finding.affectedPolicies.length > 0
                                ? `
                                <div class="finding-detail" style="margin-top: 12px;">
                                    <div class="finding-detail-label">Affected Policies</div>
                                    <div class="finding-detail-value">${finding.affectedPolicies.map(escapeHtml).join(', ')}</div>
                                </div>
                            `
                                : ''
                            }
                            ${
                              finding.references && finding.references.length > 0
                                ? `
                                <div class="finding-references">
                                    <div class="finding-detail-label">References</div>
                                    ${finding.references.map((ref) => `<a href="${escapeHtml(ref)}" target="_blank">${escapeHtml(ref)}</a>`).join('')}
                                </div>
                            `
                                : ''
                            }
                        </div>
                    `
                      )
                      .join('')}
                </div>
            `
                    )
                    .join('')
            }
        </section>

        <footer class="footer">
            Generated by Azure CA Policy Analyzer | ${new Date().toISOString().split('T')[0]}<br>
            This report is confidential and intended for authorized personnel only.
        </footer>
    </div>
</body>
</html>`;
}

export function generateJsonReport(result: AnalysisResult): string {
  return JSON.stringify(result, null, 2);
}

export function generateMarkdownReport(
  result: AnalysisResult,
  tenantName: string = 'Your Organization'
): string {
  const { findings, summary } = result;

  let md = `# Azure Conditional Access Policy Analysis

**Organization:** ${tenantName}
**Analysis Date:** ${result.analyzedAt}
**Security Score:** ${summary.securityScore}/100

## Summary

| Metric | Value |
|--------|-------|
| Total Policies | ${result.totalPolicies} |
| Enabled Policies | ${result.enabledPolicies} |
| Report-Only Policies | ${result.reportOnlyPolicies} |
| Disabled Policies | ${result.disabledPolicies} |
| Total Findings | ${findings.length} |

### Findings by Severity

| Severity | Count |
|----------|-------|
| Critical | ${summary.criticalCount} |
| High | ${summary.highCount} |
| Medium | ${summary.mediumCount} |
| Low | ${summary.lowCount} |
| Info | ${summary.infoCount} |

## Findings

`;

  // Group by severity
  const severityOrder: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

  for (const severity of severityOrder) {
    const severityFindings = findings.filter((f) => f.severity === severity);
    if (severityFindings.length === 0) continue;

    md += `### ${severity} (${severityFindings.length})\n\n`;

    for (const finding of severityFindings) {
      md += `#### ${finding.id}: ${finding.title}\n\n`;
      md += `**Category:** ${finding.category}\n\n`;
      md += `${finding.description}\n\n`;
      md += `**Impact:** ${finding.impact}\n\n`;
      md += `**Remediation:** ${finding.remediation}\n\n`;

      if (finding.affectedPolicies && finding.affectedPolicies.length > 0) {
        md += `**Affected Policies:** ${finding.affectedPolicies.join(', ')}\n\n`;
      }

      if (finding.references && finding.references.length > 0) {
        md += `**References:**\n`;
        for (const ref of finding.references) {
          md += `- ${ref}\n`;
        }
        md += '\n';
      }

      md += '---\n\n';
    }
  }

  return md;
}
