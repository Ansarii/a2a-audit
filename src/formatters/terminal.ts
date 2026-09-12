import { AuditReport, SecurityFinding, SeverityLevel } from '../types';

const ANSI = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  bgRed: '\x1b[41m',
  bgGreen: '\x1b[42m',
  bgYellow: '\x1b[43m'
};

function getSeverityBadge(severity: SeverityLevel): string {
  switch (severity) {
    case 'CRITICAL':
      return `${ANSI.bgRed}${ANSI.white}${ANSI.bold} CRITICAL ${ANSI.reset}`;
    case 'HIGH':
      return `${ANSI.red}${ANSI.bold}[HIGH]${ANSI.reset}`;
    case 'MEDIUM':
      return `${ANSI.yellow}${ANSI.bold}[MEDIUM]${ANSI.reset}`;
    case 'LOW':
      return `${ANSI.blue}${ANSI.bold}[LOW]${ANSI.reset}`;
    case 'INFO':
      return `${ANSI.dim}[INFO]${ANSI.reset}`;
  }
}

function getGradeBadge(grade: string): string {
  switch (grade) {
    case 'A+':
    case 'A':
      return `${ANSI.green}${ANSI.bold}${grade}${ANSI.reset}`;
    case 'B':
      return `${ANSI.cyan}${ANSI.bold}${grade}${ANSI.reset}`;
    case 'C':
      return `${ANSI.yellow}${ANSI.bold}${grade}${ANSI.reset}`;
    case 'D':
    case 'F':
      return `${ANSI.red}${ANSI.bold}${grade}${ANSI.reset}`;
    default:
      return grade;
  }
}

export function formatTerminalReport(report: AuditReport): string {
  const lines: string[] = [];

  lines.push('');
  lines.push(`${ANSI.cyan}${ANSI.bold}╔════════════════════════════════════════════════════════════════════════════╗${ANSI.reset}`);
  lines.push(`${ANSI.cyan}${ANSI.bold}║                 A2A AGENT CARD SECURITY AUDIT REPORT                       ║${ANSI.reset}`);
  lines.push(`${ANSI.cyan}${ANSI.bold}╚════════════════════════════════════════════════════════════════════════════╝${ANSI.reset}`);
  lines.push('');

  lines.push(`  ${ANSI.bold}Target:${ANSI.reset}           ${report.target}`);
  lines.push(`  ${ANSI.bold}Agent Name:${ANSI.reset}       ${report.agentMetadata.name || '(unnamed)'}`);
  lines.push(`  ${ANSI.bold}Version:${ANSI.reset}          ${report.agentMetadata.version || '(unversioned)'}`);
  lines.push(`  ${ANSI.bold}Provider:${ANSI.reset}         ${report.agentMetadata.provider || '(none)'}`);
  lines.push(`  ${ANSI.bold}Skills Audited:${ANSI.reset}   ${report.agentMetadata.skillsCount}`);
  lines.push(`  ${ANSI.bold}Interfaces:${ANSI.reset}       ${report.agentMetadata.interfacesCount}`);
  lines.push(`  ${ANSI.bold}Timestamp:${ANSI.reset}        ${report.scanTimestamp}`);
  lines.push('');

  // Score Box
  const passText = report.passed
    ? `${ANSI.bgGreen}${ANSI.white}${ANSI.bold} PASSED ${ANSI.reset}`
    : `${ANSI.bgRed}${ANSI.white}${ANSI.bold} FAILED ${ANSI.reset}`;

  lines.push(`  ┌──────────────────────────────────────────────────────────┐`);
  lines.push(`  │  Trust Score: ${ANSI.bold}${String(report.trustScore).padStart(3)}/100${ANSI.reset}   Grade: ${getGradeBadge(report.grade)}   Verdict: ${passText} │`);
  lines.push(`  └──────────────────────────────────────────────────────────┘`);
  lines.push('');

  // Findings Section
  if (report.findings.length === 0) {
    lines.push(`  ${ANSI.green}${ANSI.bold}✔ No security vulnerabilities found! 100% compliant with A2A specification.${ANSI.reset}`);
    lines.push('');
  } else {
    lines.push(`  ${ANSI.bold}Findings (${report.findings.length}):${ANSI.reset}`);
    lines.push('');

    report.findings.forEach((f, i) => {
      lines.push(`  ${i + 1}. ${getSeverityBadge(f.severity)} ${ANSI.bold}${f.ruleId} - ${f.ruleName}${ANSI.reset}`);
      lines.push(`     ${ANSI.dim}Field:${ANSI.reset} ${f.field}`);
      lines.push(`     ${ANSI.bold}Issue:${ANSI.reset} ${f.message}`);
      if (f.cwe) {
        lines.push(`     ${ANSI.dim}CWE:${ANSI.reset} ${f.cwe}`);
      }
      if (f.aiTechTaxonomy) {
        lines.push(`     ${ANSI.dim}Taxonomy:${ANSI.reset} ${f.aiTechTaxonomy}`);
      }
      lines.push(`     ${ANSI.green}Fix:${ANSI.reset} ${f.remediation}`);
      lines.push('');
    });
  }

  // Summary Footer
  lines.push(`  ${ANSI.dim}────────────────────────────────────────────────────────────${ANSI.reset}`);
  lines.push(`  ${ANSI.bold}Summary:${ANSI.reset} ${report.summary.critical} Critical, ${report.summary.high} High, ${report.summary.medium} Medium, ${report.summary.low} Low`);
  lines.push(`  ${ANSI.dim}Run with --format sarif for GitHub Advanced Security ingestion.${ANSI.reset}`);
  lines.push('');

  return lines.join('\n');
}
