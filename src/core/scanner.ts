import * as fs from 'fs';
import * as path from 'path';
import * as http from 'http';
import * as https from 'https';
import { AgentCard, AuditReport, ScanOptions, SecurityFinding } from '../types';
import { executeAllRules } from './rules';
import { calculateScoreAndGrade } from './scoring';

/**
 * Fetches JSON content from a remote HTTP(S) URL with redirect support and timeout
 */
async function fetchRemoteJson(urlStr: string, timeoutMs = 10000): Promise<string> {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(urlStr);
    const client = parsedUrl.protocol === 'https:' ? https : http;

    const req = client.get(
      urlStr,
      {
        headers: {
          'User-Agent': 'a2a-audit/1.0.0 (+https://github.com/Ansarii/a2a-audit)',
          'Accept': 'application/json, application/a2a+json, */*'
        },
        timeout: timeoutMs
      },
      (res) => {
        // Handle HTTP redirects (301, 302, 307, 308)
        if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          const redirectUrl = new URL(res.headers.location, urlStr).toString();
          fetchRemoteJson(redirectUrl, timeoutMs).then(resolve).catch(reject);
          return;
        }

        if (res.statusCode && (res.statusCode < 200 || res.statusCode >= 300)) {
          reject(new Error(`HTTP ${res.statusCode} ${res.statusMessage || 'Error'} fetching ${urlStr}`));
          return;
        }

        let rawData = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          rawData += chunk;
        });
        res.on('end', () => {
          resolve(rawData);
        });
      }
    );

    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`Request timeout after ${timeoutMs}ms fetching ${urlStr}`));
    });

    req.on('error', (err) => {
      reject(err);
    });
  });
}

/**
 * Main scanner function: parses and audits an Agent Card from local file or remote URL
 */
export async function auditAgentCard(target: string, options: ScanOptions = {}): Promise<AuditReport> {
  const timestamp = new Date().toISOString();
  let rawJson = '';
  const isUrl = target.startsWith('http://') || target.startsWith('https://');

  try {
    if (isUrl) {
      rawJson = await fetchRemoteJson(target, options.timeoutMs || 10000);
    } else if (fs.existsSync(target)) {
      const resolvedPath = path.resolve(process.cwd(), target);
      rawJson = fs.readFileSync(resolvedPath, 'utf8');
    } else {
      // Attempt to treat target directly as a raw JSON string
      rawJson = target.trim();
    }
  } catch (err: any) {
    const criticalFinding: SecurityFinding = {
      ruleId: 'A2A-ERR-001',
      ruleName: 'TARGET_FETCH_ERROR',
      severity: 'CRITICAL',
      message: `Failed to retrieve Agent Card from "${target}": ${err.message}`,
      field: 'target',
      remediation: 'Verify that the file path exists or the remote URL is accessible and returns a valid HTTP 200.'
    };

    const scoring = calculateScoreAndGrade([criticalFinding], options.strict);
    return {
      target,
      scanTimestamp: timestamp,
      trustScore: 0,
      grade: 'F',
      passed: false,
      summary: scoring.summary,
      agentMetadata: { skillsCount: 0, interfacesCount: 0 },
      findings: [criticalFinding]
    };
  }

  let parsedCard: AgentCard;
  try {
    parsedCard = JSON.parse(rawJson);
  } catch (err: any) {
    const parseFinding: SecurityFinding = {
      ruleId: 'A2A-ERR-002',
      ruleName: 'MALFORMED_JSON_DOCUMENT',
      severity: 'CRITICAL',
      message: `Invalid JSON format in Agent Card: ${err.message}`,
      field: 'root',
      remediation: 'Fix JSON syntax errors to conform with standard JSON specification (RFC 8259).'
    };

    const scoring = calculateScoreAndGrade([parseFinding], options.strict);
    return {
      target,
      scanTimestamp: timestamp,
      trustScore: 0,
      grade: 'F',
      passed: false,
      summary: scoring.summary,
      agentMetadata: { skillsCount: 0, interfacesCount: 0 },
      findings: [parseFinding]
    };
  }

  // Execute all 10 security detection rules
  const findings = executeAllRules(parsedCard);

  // Compute Trust Score & Letter Grade
  const scoreResult = calculateScoreAndGrade(findings, options.strict);

  const interfaces = parsedCard.supportedInterfaces || parsedCard.supported_interfaces || [];
  const skills = parsedCard.skills || [];

  return {
    target,
    scanTimestamp: timestamp,
    trustScore: scoreResult.trustScore,
    grade: scoreResult.grade,
    passed: scoreResult.passed,
    summary: scoreResult.summary,
    agentMetadata: {
      name: parsedCard.name,
      version: parsedCard.version,
      provider: parsedCard.provider?.organization || parsedCard.provider?.url,
      skillsCount: skills.length,
      interfacesCount: interfaces.length
    },
    findings
  };
}
