"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.auditAgentCard = auditAgentCard;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const http = __importStar(require("http"));
const https = __importStar(require("https"));
const rules_1 = require("./rules");
const scoring_1 = require("./scoring");
/**
 * Fetches JSON content from a remote HTTP(S) URL with redirect support and timeout
 */
async function fetchRemoteJson(urlStr, timeoutMs = 10000) {
    return new Promise((resolve, reject) => {
        const parsedUrl = new URL(urlStr);
        const client = parsedUrl.protocol === 'https:' ? https : http;
        const req = client.get(urlStr, {
            headers: {
                'User-Agent': 'a2a-audit/1.0.0 (+https://github.com/Ansarii/a2a-audit)',
                'Accept': 'application/json, application/a2a+json, */*'
            },
            timeout: timeoutMs
        }, (res) => {
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
        });
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
async function auditAgentCard(target, options = {}) {
    const timestamp = new Date().toISOString();
    let rawJson = '';
    const isUrl = target.startsWith('http://') || target.startsWith('https://');
    try {
        if (isUrl) {
            rawJson = await fetchRemoteJson(target, options.timeoutMs || 10000);
        }
        else if (fs.existsSync(target)) {
            const resolvedPath = path.resolve(process.cwd(), target);
            rawJson = fs.readFileSync(resolvedPath, 'utf8');
        }
        else {
            // Attempt to treat target directly as a raw JSON string
            rawJson = target.trim();
        }
    }
    catch (err) {
        const criticalFinding = {
            ruleId: 'A2A-ERR-001',
            ruleName: 'TARGET_FETCH_ERROR',
            severity: 'CRITICAL',
            message: `Failed to retrieve Agent Card from "${target}": ${err.message}`,
            field: 'target',
            remediation: 'Verify that the file path exists or the remote URL is accessible and returns a valid HTTP 200.'
        };
        const scoring = (0, scoring_1.calculateScoreAndGrade)([criticalFinding], options.strict);
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
    let parsedCard;
    try {
        parsedCard = JSON.parse(rawJson);
    }
    catch (err) {
        const parseFinding = {
            ruleId: 'A2A-ERR-002',
            ruleName: 'MALFORMED_JSON_DOCUMENT',
            severity: 'CRITICAL',
            message: `Invalid JSON format in Agent Card: ${err.message}`,
            field: 'root',
            remediation: 'Fix JSON syntax errors to conform with standard JSON specification (RFC 8259).'
        };
        const scoring = (0, scoring_1.calculateScoreAndGrade)([parseFinding], options.strict);
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
    const findings = (0, rules_1.executeAllRules)(parsedCard);
    // Compute Trust Score & Letter Grade
    const scoreResult = (0, scoring_1.calculateScoreAndGrade)(findings, options.strict);
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
//# sourceMappingURL=scanner.js.map