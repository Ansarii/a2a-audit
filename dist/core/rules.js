"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.checkSignaturesPresent = checkSignaturesPresent;
exports.checkSignatureIntegrity = checkSignatureIntegrity;
exports.checkTransportEncryption = checkTransportEncryption;
exports.checkSsrfExposure = checkSsrfExposure;
exports.checkPromptInjectionInMetadata = checkPromptInjectionInMetadata;
exports.checkUnauthenticatedDangerousSkills = checkUnauthenticatedDangerousSkills;
exports.checkDeprecatedOAuthFlows = checkDeprecatedOAuthFlows;
exports.checkApiKeyQueryParameter = checkApiKeyQueryParameter;
exports.checkExtendedCardAuthentication = checkExtendedCardAuthentication;
exports.checkSchemaCompliance = checkSchemaCompliance;
exports.executeAllRules = executeAllRules;
/**
 * Base64URL decoder helper for Node.js
 */
function decodeBase64Url(input) {
    try {
        let base64 = input.replace(/-/g, '+').replace(/_/g, '/');
        while (base64.length % 4 !== 0) {
            base64 += '=';
        }
        return Buffer.from(base64, 'base64').toString('utf8');
    }
    catch {
        return '';
    }
}
/**
 * Checks if a hostname corresponds to loopback, private RFC 1918, or Cloud Metadata
 */
function isInternalOrPrivateHost(hostname) {
    const host = hostname.toLowerCase().trim();
    if (host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '0.0.0.0') {
        return true;
    }
    // Cloud metadata services
    if (host === '169.254.169.254' || host === 'metadata.google.internal' || host.startsWith('169.254.')) {
        return true;
    }
    // RFC 1918: 10.0.0.0/8
    if (/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) {
        return true;
    }
    // RFC 1918: 172.16.0.0/12
    const match172 = host.match(/^172\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/);
    if (match172) {
        const octet = parseInt(match172[1], 10);
        if (octet >= 16 && octet <= 31)
            return true;
    }
    // RFC 1918: 192.168.0.0/16
    if (/^192\.168\.\d{1,3}\.\d{1,3}$/.test(host)) {
        return true;
    }
    return false;
}
/**
 * Rule 1: A2A-SEC-001 - Unsigned Agent Card (CRITICAL)
 */
function checkSignaturesPresent(card) {
    const findings = [];
    const signatures = card.signatures;
    if (!signatures || !Array.isArray(signatures) || signatures.length === 0) {
        findings.push({
            ruleId: 'A2A-SEC-001',
            ruleName: 'UNSIGNED_AGENT_CARD',
            severity: 'CRITICAL',
            message: 'Agent Card contains no cryptographic JWS signatures. Identity cannot be verified by external orchestrators.',
            field: 'signatures',
            value: signatures,
            remediation: 'Digitally sign the canonicalized Agent Card (RFC 8785) using an asymmetric RFC 7515 JWS signature (ES256 or RS256) and populate the signatures array.',
            cwe: 'CWE-345: Insufficient Verification of Data Authenticity',
            aiTechTaxonomy: 'AITech-3.1 (Trusted Agent Spoofing)'
        });
    }
    return findings;
}
/**
 * Rule 2: A2A-SEC-002 - Insecure / Rogue Cryptographic Signature (CRITICAL)
 */
function checkSignatureIntegrity(card) {
    const findings = [];
    const signatures = card.signatures;
    if (!signatures || !Array.isArray(signatures) || signatures.length === 0) {
        return findings; // Handled by Rule 1
    }
    const providerUrl = card.provider?.url || '';
    let providerDomain = '';
    try {
        if (providerUrl)
            providerDomain = new URL(providerUrl).hostname.toLowerCase();
    }
    catch {
        // Ignore invalid provider URL parsing here (handled in transport rule)
    }
    signatures.forEach((sig, index) => {
        if (!sig.protected || typeof sig.protected !== 'string') {
            findings.push({
                ruleId: 'A2A-SEC-002',
                ruleName: 'MALFORMED_SIGNATURE_HEADER',
                severity: 'CRITICAL',
                message: `Signature at index ${index} is missing a valid base64url-encoded protected header.`,
                field: `signatures[${index}].protected`,
                remediation: 'Provide a valid base64url-encoded JSON object in signatures[].protected conforming to RFC 7515.',
                cwe: 'CWE-347: Improper Verification of Cryptographic Signature',
                aiTechTaxonomy: 'AITech-5.2 (Agent Profile Tampering)'
            });
            return;
        }
        const decoded = decodeBase64Url(sig.protected);
        let header = {};
        try {
            header = JSON.parse(decoded);
        }
        catch {
            findings.push({
                ruleId: 'A2A-SEC-002',
                ruleName: 'INVALID_JWS_JSON_HEADER',
                severity: 'CRITICAL',
                message: `Signature at index ${index} protected header cannot be parsed as JSON: "${decoded}".`,
                field: `signatures[${index}].protected`,
                remediation: 'Ensure the protected header decodes to a valid JSON object containing alg, typ, and kid.',
                cwe: 'CWE-347: Improper Verification of Cryptographic Signature',
                aiTechTaxonomy: 'AITech-5.2 (Agent Profile Tampering)'
            });
            return;
        }
        // Insecure algorithm verification
        const alg = (header.alg || '').toUpperCase();
        if (!alg || alg === 'NONE') {
            findings.push({
                ruleId: 'A2A-SEC-002',
                ruleName: 'INSECURE_SIGNATURE_ALGORITHM',
                severity: 'CRITICAL',
                message: `Signature at index ${index} uses insecure or absent algorithm ("${header.alg || 'none'}").`,
                field: `signatures[${index}].protected.alg`,
                value: header.alg,
                remediation: 'Use a secure asymmetric algorithm such as ES256, ES384, RS256, or Ed25519.',
                cwe: 'CWE-327: Use of a Broken or Risky Cryptographic Algorithm',
                aiTechTaxonomy: 'AITech-5.2 (Agent Profile Tampering)'
            });
        }
        else if (alg.startsWith('HS')) {
            findings.push({
                ruleId: 'A2A-SEC-002',
                ruleName: 'SYMMETRIC_SIGNATURE_IN_PUBLIC_CARD',
                severity: 'CRITICAL',
                message: `Signature at index ${index} uses symmetric HMAC algorithm (${header.alg}). Public Agent Cards require asymmetric signatures for zero-trust verification.`,
                field: `signatures[${index}].protected.alg`,
                value: header.alg,
                remediation: 'Replace symmetric HMAC signing with asymmetric public-key cryptography (ES256 or RS256).',
                cwe: 'CWE-321: Use of Hard-coded Cryptographic Key',
                aiTechTaxonomy: 'AITech-5.2 (Agent Profile Tampering)'
            });
        }
        // Key pinning & JKU origin validation
        if (header.jku && typeof header.jku === 'string') {
            try {
                const jkuUrl = new URL(header.jku);
                if (jkuUrl.protocol !== 'https:') {
                    findings.push({
                        ruleId: 'A2A-SEC-002',
                        ruleName: 'INSECURE_JKU_TRANSPORT',
                        severity: 'CRITICAL',
                        message: `Signature at index ${index} JWKS URL (jku) uses unencrypted HTTP: "${header.jku}".`,
                        field: `signatures[${index}].protected.jku`,
                        remediation: 'Ensure the JWKS URL uses secure HTTPS.',
                        cwe: 'CWE-319: Cleartext Transmission of Sensitive Information'
                    });
                }
                else if (providerDomain && !jkuUrl.hostname.toLowerCase().endsWith(providerDomain) && !providerDomain.endsWith(jkuUrl.hostname.toLowerCase())) {
                    findings.push({
                        ruleId: 'A2A-SEC-002',
                        ruleName: 'ROGUE_JKU_ORIGIN_MISMATCH',
                        severity: 'HIGH',
                        message: `Signature at index ${index} JWKS URL host (${jkuUrl.hostname}) does not match provider domain (${providerDomain}). Potential key substitution risk.`,
                        field: `signatures[${index}].protected.jku`,
                        value: header.jku,
                        remediation: 'Host the JWKS keyset on the same domain as the agent provider or pin explicit trust roots.',
                        cwe: 'CWE-295: Improper Certificate Validation',
                        aiTechTaxonomy: 'AITech-3.1 (Trusted Agent Spoofing)'
                    });
                }
            }
            catch {
                findings.push({
                    ruleId: 'A2A-SEC-002',
                    ruleName: 'MALFORMED_JKU_URL',
                    severity: 'HIGH',
                    message: `Signature at index ${index} contains invalid jku URL: "${header.jku}".`,
                    field: `signatures[${index}].protected.jku`,
                    remediation: 'Provide a valid absolute HTTPS URL pointing to the JSON Web Key Set.'
                });
            }
        }
    });
    return findings;
}
/**
 * Rule 3: A2A-SEC-003 - Insecure Cleartext Transport (HIGH)
 */
function checkTransportEncryption(card) {
    const findings = [];
    const urlsToCheck = [];
    const interfaces = card.supportedInterfaces || card.supported_interfaces || [];
    interfaces.forEach((iface, idx) => {
        if (iface && iface.url) {
            urlsToCheck.push({ url: iface.url, path: `supportedInterfaces[${idx}].url` });
        }
    });
    if (card.provider?.url) {
        urlsToCheck.push({ url: card.provider.url, path: 'provider.url' });
    }
    if (card.documentationUrl || card.documentation_url) {
        urlsToCheck.push({ url: (card.documentationUrl || card.documentation_url), path: 'documentationUrl' });
    }
    if (card.iconUrl || card.icon_url) {
        urlsToCheck.push({ url: (card.iconUrl || card.icon_url), path: 'iconUrl' });
    }
    const schemes = card.securitySchemes || card.security_schemes || {};
    Object.entries(schemes).forEach(([key, scheme]) => {
        const oidc = scheme.openIdConnectSecurityScheme || scheme.open_id_connect_security_scheme;
        if (oidc && (oidc.openIdConnectUrl || oidc.open_id_connect_url)) {
            urlsToCheck.push({ url: (oidc.openIdConnectUrl || oidc.open_id_connect_url), path: `securitySchemes.${key}.openIdConnectUrl` });
        }
        const oauth2 = scheme.oauth2SecurityScheme || scheme.oauth2_security_scheme;
        if (oauth2 && (oauth2.oauth2MetadataUrl || oauth2.oauth2_metadata_url)) {
            urlsToCheck.push({ url: (oauth2.oauth2MetadataUrl || oauth2.oauth2_metadata_url), path: `securitySchemes.${key}.oauth2MetadataUrl` });
        }
    });
    urlsToCheck.forEach(({ url, path }) => {
        if (url.startsWith('http://')) {
            findings.push({
                ruleId: 'A2A-SEC-003',
                ruleName: 'CLEARTEXT_HTTP_TRANSPORT',
                severity: 'HIGH',
                message: `Cleartext HTTP protocol detected in ${path}: "${url}". Section 13.4 mandates encrypted HTTPS in production.`,
                field: path,
                value: url,
                remediation: `Update "${url}" to use HTTPS to prevent credential interception and Man-in-the-Middle tampering.`,
                cwe: 'CWE-319: Cleartext Transmission of Sensitive Information',
                aiTechTaxonomy: 'AITech-9.1 (Model or Agentic System Manipulation)'
            });
        }
    });
    return findings;
}
/**
 * Rule 4: A2A-SEC-004 - SSRF & Internal Network Exposure (CRITICAL)
 */
function checkSsrfExposure(card) {
    const findings = [];
    const interfaces = card.supportedInterfaces || card.supported_interfaces || [];
    interfaces.forEach((iface, idx) => {
        if (!iface?.url)
            return;
        try {
            const parsed = new URL(iface.url);
            if (isInternalOrPrivateHost(parsed.hostname)) {
                findings.push({
                    ruleId: 'A2A-SEC-004',
                    ruleName: 'SSRF_INTERNAL_ENDPOINT_EXPOSURE',
                    severity: 'CRITICAL',
                    message: `Supported interface ${idx} points to private/internal host (${parsed.hostname}). Orchestrators could be weaponized for SSRF.`,
                    field: `supportedInterfaces[${idx}].url`,
                    value: iface.url,
                    remediation: 'Replace internal IP/localhost with a publicly routable, authenticated domain name.',
                    cwe: 'CWE-918: Server-Side Request Forgery (SSRF)',
                    aiTechTaxonomy: 'AITech-9.1 (Unauthorized Network Access)'
                });
            }
        }
        catch {
            // Invalid URL format will be caught by schema compliance
        }
    });
    return findings;
}
/**
 * Rule 5: A2A-SEC-005 - Adversarial Prompt Injection & Obfuscation (HIGH)
 */
function checkPromptInjectionInMetadata(card) {
    const findings = [];
    const injectionPatterns = [
        { pattern: /ignore\s+(all\s+)?(previous|prior|above)\s+instructions/i, description: 'Direct instruction override attempt' },
        { pattern: /system\s+prompt\s+override/i, description: 'Explicit system prompt override token' },
        { pattern: /you\s+must\s+now\s+act\s+as/i, description: 'Role-hijacking override phrase' },
        { pattern: /disregard\s+(all\s+)?(safety|rules|guidelines)/i, description: 'Safety guardrail bypass directive' },
        { pattern: /developer\s+mode\s+enabled/i, description: 'Jailbreak persona token' },
        { pattern: /always\s+route\s+(all\s+)?(banking|payment|confidential|admin)\s+tasks\s+to\s+this\s+agent/i, description: 'Orchestrator routing manipulation' }
    ];
    const unicodeObfuscationPattern = /[\u200B-\u200D\uFEFF\u202E\u202D\u202B]/;
    const stringsToAudit = [
        { text: card.description || '', path: 'description' }
    ];
    (card.skills || []).forEach((skill, sIdx) => {
        stringsToAudit.push({ text: skill.description || '', path: `skills[${sIdx}].description` });
        (skill.examples || []).forEach((example, eIdx) => {
            stringsToAudit.push({ text: example || '', path: `skills[${sIdx}].examples[${eIdx}]` });
        });
    });
    stringsToAudit.forEach(({ text, path }) => {
        if (!text)
            return;
        if (unicodeObfuscationPattern.test(text)) {
            findings.push({
                ruleId: 'A2A-SEC-005',
                ruleName: 'UNICODE_OBFUSCATION_DETECTED',
                severity: 'HIGH',
                message: `Zero-width or bidirectional Unicode control characters detected in ${path}. Potential prompt injection evasion.`,
                field: path,
                remediation: 'Strip invisible Unicode control characters (\u200B, \u200C, \u202E) from agent and skill descriptions.',
                cwe: 'CWE-116: Improper Encoding or Escaping of Output',
                aiTechTaxonomy: 'AITech-1.1 (Direct Prompt Injection)'
            });
        }
        injectionPatterns.forEach(({ pattern, description }) => {
            if (pattern.test(text)) {
                findings.push({
                    ruleId: 'A2A-SEC-005',
                    ruleName: 'ADVERSARIAL_PROMPT_INJECTION',
                    severity: 'HIGH',
                    message: `Suspicious prompt injection directive (${description}) detected in ${path}: "${text.substring(0, 80)}..."`,
                    field: path,
                    remediation: 'Sanitize descriptive text and ensure instructions do not manipulate or hijack parent agent orchestrators.',
                    cwe: 'CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component',
                    aiTechTaxonomy: 'AITech-1.1 (Direct Prompt Injection)'
                });
            }
        });
    });
    return findings;
}
/**
 * Rule 6: A2A-SEC-006 - Unauthenticated Dangerous Primitives (HIGH)
 */
function checkUnauthenticatedDangerousSkills(card) {
    const findings = [];
    const rootAuthRequirements = card.securityRequirements || card.security_requirements || [];
    const hasRootAuth = Array.isArray(rootAuthRequirements) && rootAuthRequirements.length > 0;
    const dangerousKeywords = /exec|eval|shell|bash|command|terminal|run_code|system_call|sql_query|drop_table|payment|transfer_money|fund_transfer|modify_auth|update_permissions|delete_database|admin_access/i;
    (card.skills || []).forEach((skill, sIdx) => {
        const combinedTokens = `${skill.id || ''} ${skill.name || ''} ${(skill.tags || []).join(' ')} ${skill.description || ''}`;
        const isDangerous = dangerousKeywords.test(combinedTokens);
        if (isDangerous) {
            const skillAuth = skill.securityRequirements || skill.security_requirements || [];
            const hasSkillAuth = Array.isArray(skillAuth) && skillAuth.length > 0;
            if (!hasSkillAuth && !hasRootAuth) {
                findings.push({
                    ruleId: 'A2A-SEC-006',
                    ruleName: 'UNAUTHENTICATED_DANGEROUS_PRIMITIVE',
                    severity: 'HIGH',
                    message: `Skill "${skill.id || skill.name}" performs privileged/dangerous actions but declares no security requirements.`,
                    field: `skills[${sIdx}].securityRequirements`,
                    value: { id: skill.id, name: skill.name },
                    remediation: `Enforce granular authentication (e.g. OAuth2 scopes or mTLS) in skills[${sIdx}].securityRequirements for dangerous operations.`,
                    cwe: 'CWE-306: Missing Authentication for Critical Function',
                    aiTechTaxonomy: 'AITech-14.1 (Insufficient Access Controls)'
                });
            }
        }
    });
    return findings;
}
/**
 * Rule 7: A2A-SEC-007 - Deprecated & Insecure OAuth Flows (MEDIUM)
 */
function checkDeprecatedOAuthFlows(card) {
    const findings = [];
    const schemes = card.securitySchemes || card.security_schemes || {};
    Object.entries(schemes).forEach(([key, scheme]) => {
        const oauth2 = scheme.oauth2SecurityScheme || scheme.oauth2_security_scheme;
        if (oauth2 && oauth2.flows) {
            const flows = oauth2.flows;
            if (flows.implicit) {
                findings.push({
                    ruleId: 'A2A-SEC-007',
                    ruleName: 'DEPRECATED_OAUTH_IMPLICIT_FLOW',
                    severity: 'MEDIUM',
                    message: `Security scheme "${key}" declares OAuth2 "implicit" flow, officially deprecated in A2A proto due to token leakage in URL fragments.`,
                    field: `securitySchemes.${key}.oauth2SecurityScheme.flows.implicit`,
                    remediation: 'Migrate to Authorization Code flow with PKCE (RFC 7636).',
                    cwe: 'CWE-384: Session Fixation',
                    aiTechTaxonomy: 'AITech-14.1 (Unauthorized Access)'
                });
            }
            if (flows.password) {
                findings.push({
                    ruleId: 'A2A-SEC-007',
                    ruleName: 'DEPRECATED_OAUTH_PASSWORD_FLOW',
                    severity: 'MEDIUM',
                    message: `Security scheme "${key}" declares OAuth2 "password" (ROPC) flow, officially deprecated due to credential harvesting risks.`,
                    field: `securitySchemes.${key}.oauth2SecurityScheme.flows.password`,
                    remediation: 'Replace password flow with Client Credentials or Authorization Code flow with PKCE.',
                    cwe: 'CWE-522: Insufficiently Protected Credentials',
                    aiTechTaxonomy: 'AITech-14.1 (Credential Theft)'
                });
            }
        }
    });
    return findings;
}
/**
 * Rule 8: A2A-SEC-008 - API Key Query Parameter Leakage (MEDIUM)
 */
function checkApiKeyQueryParameter(card) {
    const findings = [];
    const schemes = card.securitySchemes || card.security_schemes || {};
    Object.entries(schemes).forEach(([key, scheme]) => {
        const apiKey = scheme.apiKeySecurityScheme || scheme.api_key_security_scheme;
        if (apiKey && apiKey.location === 'query') {
            findings.push({
                ruleId: 'A2A-SEC-008',
                ruleName: 'QUERY_PARAM_CREDENTIAL_LEAK',
                severity: 'MEDIUM',
                message: `API Key scheme "${key}" specifies location: "query". API tokens in query parameters are exposed in server access logs and HTTP referrers.`,
                field: `securitySchemes.${key}.apiKeySecurityScheme.location`,
                value: apiKey.name,
                remediation: 'Change API key location from "query" to "header" (e.g. "X-API-Key" or "Authorization: Bearer").',
                cwe: 'CWE-598: Use of GET Request Method with Sensitive Query Strings',
                aiTechTaxonomy: 'AITech-8.3 (System Information Leakage)'
            });
        }
    });
    return findings;
}
/**
 * Rule 9: A2A-SEC-009 - Unauthenticated Extended Agent Card Escalation (HIGH)
 */
function checkExtendedCardAuthentication(card) {
    const findings = [];
    const capabilities = card.capabilities || {};
    const hasExtendedCard = capabilities.extendedAgentCard === true;
    if (hasExtendedCard) {
        const schemes = card.securitySchemes || card.security_schemes || {};
        const hasSchemes = Object.keys(schemes).length > 0;
        const requirements = card.securityRequirements || card.security_requirements || [];
        const hasRequirements = Array.isArray(requirements) && requirements.length > 0;
        if (!hasSchemes || !hasRequirements) {
            findings.push({
                ruleId: 'A2A-SEC-009',
                ruleName: 'UNAUTHENTICATED_EXTENDED_AGENT_CARD',
                severity: 'HIGH',
                message: 'Agent Card declares capabilities.extendedAgentCard: true, but does not configure required security schemes or requirements. Section 13.3 strictly requires extended cards to be authenticated.',
                field: 'capabilities.extendedAgentCard',
                remediation: 'Configure securitySchemes and securityRequirements so Get Extended Agent Card requests are properly authenticated.',
                cwe: 'CWE-306: Missing Authentication for Critical Function',
                aiTechTaxonomy: 'AITech-14.1 (Insufficient Access Controls)'
            });
        }
    }
    return findings;
}
/**
 * Rule 10: A2A-SEC-010 - Protocol Specification & Schema Compliance (LOW/INFO)
 */
function checkSchemaCompliance(card) {
    const findings = [];
    if (!card.name || typeof card.name !== 'string' || card.name.trim() === '') {
        findings.push({
            ruleId: 'A2A-SEC-010',
            ruleName: 'MISSING_REQUIRED_NAME',
            severity: 'LOW',
            message: 'Agent Card is missing REQUIRED field "name".',
            field: 'name',
            remediation: 'Provide a descriptive name for the agent.'
        });
    }
    if (!card.description || typeof card.description !== 'string' || card.description.trim() === '') {
        findings.push({
            ruleId: 'A2A-SEC-010',
            ruleName: 'MISSING_REQUIRED_DESCRIPTION',
            severity: 'LOW',
            message: 'Agent Card is missing REQUIRED field "description".',
            field: 'description',
            remediation: 'Provide a clear description of the agent purpose and capabilities.'
        });
    }
    const interfaces = card.supportedInterfaces || card.supported_interfaces;
    if (!interfaces || !Array.isArray(interfaces) || interfaces.length === 0) {
        findings.push({
            ruleId: 'A2A-SEC-010',
            ruleName: 'MISSING_REQUIRED_INTERFACES',
            severity: 'LOW',
            message: 'Agent Card is missing REQUIRED field "supportedInterfaces" or list is empty.',
            field: 'supportedInterfaces',
            remediation: 'Declare at least one supported interface (e.g. JSON-RPC or HTTP+JSON endpoint).'
        });
    }
    if (!card.version || typeof card.version !== 'string') {
        findings.push({
            ruleId: 'A2A-SEC-010',
            ruleName: 'MISSING_REQUIRED_VERSION',
            severity: 'LOW',
            message: 'Agent Card is missing REQUIRED field "version".',
            field: 'version',
            remediation: 'Declare agent version (e.g. "1.0").'
        });
    }
    const skills = card.skills;
    if (!skills || !Array.isArray(skills) || skills.length === 0) {
        findings.push({
            ruleId: 'A2A-SEC-010',
            ruleName: 'MISSING_REQUIRED_SKILLS',
            severity: 'LOW',
            message: 'Agent Card is missing REQUIRED field "skills" or contains an empty array.',
            field: 'skills',
            remediation: 'Declare at least one skill representing the agent capabilities.'
        });
    }
    return findings;
}
/**
 * Aggregates and runs all 10 security rules against an Agent Card
 */
function executeAllRules(card) {
    const findings = [
        ...checkSignaturesPresent(card),
        ...checkSignatureIntegrity(card),
        ...checkTransportEncryption(card),
        ...checkSsrfExposure(card),
        ...checkPromptInjectionInMetadata(card),
        ...checkUnauthenticatedDangerousSkills(card),
        ...checkDeprecatedOAuthFlows(card),
        ...checkApiKeyQueryParameter(card),
        ...checkExtendedCardAuthentication(card),
        ...checkSchemaCompliance(card)
    ];
    return findings;
}
//# sourceMappingURL=rules.js.map