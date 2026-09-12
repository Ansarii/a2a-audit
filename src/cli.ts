#!/usr/bin/env node
import * as fs from 'fs';
import * as path from 'path';
import { auditAgentCard } from './core/scanner';
import { formatTerminalReport } from './formatters/terminal';
import { formatJsonReport } from './formatters/json';
import { formatSarifReport } from './formatters/sarif';
import { SeverityLevel } from './types';

function printHelp(): void {
  console.log(`
a2a-audit - Zero-Dependency DevSecOps Scanner for Agent2Agent (A2A) Cards

USAGE:
  $ npx a2a-audit <target> [options]
  $ npx a2a-audit scan <target> [options]

ARGUMENTS:
  <target>                  Local file path or remote URL to agent-card.json
                            (e.g. https://agent.example.com/.well-known/agent-card.json)

OPTIONS:
  --format, -f <type>       Output format: "terminal", "json", "sarif" (default: "terminal")
  --output, -o <file>       Write audit report to specified file
  --fail-on <level>         Fail (exit 1) if findings match severity: "critical", "high", "medium", "low" (default: "high")
  --strict                  Enable strict gating: fail on any MEDIUM findings
  --timeout <ms>            HTTP request timeout in milliseconds (default: 10000)
  --help, -h                Show this help screen
  --version, -v             Display scanner version

EXAMPLES:
  # Scan local Agent Card
  $ npx a2a-audit ./.well-known/agent-card.json

  # Scan remote live agent card
  $ npx a2a-audit scan https://agent.domain.com/.well-known/agent-card.json

  # Export SARIF for GitHub Advanced Security
  $ npx a2a-audit agent-card.json --format sarif -o results.sarif

  # CI/CD strict pull request gating
  $ npx a2a-audit ./agent-card.json --strict
`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes('-h') || args.includes('--help')) {
    printHelp();
    process.exit(0);
  }

  if (args.includes('-v') || args.includes('--version')) {
    console.log('a2a-audit v1.0.0');
    process.exit(0);
  }

  let target = '';
  let format: 'terminal' | 'json' | 'sarif' = 'terminal';
  let outputPath: string | null = null;
  let strict = false;
  let failOn: SeverityLevel = 'HIGH';
  let timeoutMs = 10000;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === 'scan') {
      continue;
    } else if (arg === '--format' || arg === '-f') {
      const val = (args[++i] || '').toLowerCase();
      if (val === 'json' || val === 'sarif' || val === 'terminal') {
        format = val;
      }
    } else if (arg === '--output' || arg === '-o') {
      outputPath = args[++i];
    } else if (arg === '--strict') {
      strict = true;
    } else if (arg === '--fail-on') {
      const level = (args[++i] || '').toUpperCase();
      if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(level)) {
        failOn = level as SeverityLevel;
      }
    } else if (arg === '--timeout') {
      const t = parseInt(args[++i], 10);
      if (!isNaN(t) && t > 0) timeoutMs = t;
    } else if (!target && !arg.startsWith('-')) {
      target = arg;
    }
  }

  if (!target) {
    console.error('Error: No target specified. Please provide a file path or URL to an Agent Card.');
    printHelp();
    process.exit(1);
  }

  try {
    const report = await auditAgentCard(target, { strict, failOn, timeoutMs });

    let outputText = '';
    switch (format) {
      case 'json':
        outputText = formatJsonReport(report);
        break;
      case 'sarif':
        outputText = formatSarifReport(report);
        break;
      case 'terminal':
      default:
        outputText = formatTerminalReport(report);
        break;
    }

    if (outputPath) {
      const fullPath = path.resolve(process.cwd(), outputPath);
      fs.writeFileSync(fullPath, outputText, 'utf8');
      if (format === 'terminal') {
        console.log(outputText);
      }
      console.log(`\nAudit report written to: ${fullPath}`);
    } else {
      console.log(outputText);
    }

    // Determine exit code
    let shouldFail = !report.passed;
    if (failOn === 'CRITICAL') {
      shouldFail = report.summary.critical > 0;
    } else if (failOn === 'HIGH') {
      shouldFail = report.summary.critical > 0 || report.summary.high > 0;
    } else if (failOn === 'MEDIUM') {
      shouldFail = report.summary.critical > 0 || report.summary.high > 0 || report.summary.medium > 0;
    }

    process.exit(shouldFail ? 1 : 0);
  } catch (err: any) {
    console.error(`Fatal scanner error: ${err.message}`);
    process.exit(1);
  }
}

main();
