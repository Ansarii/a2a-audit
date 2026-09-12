import { AgentCard, SecurityFinding } from '../types';
/**
 * Rule 1: A2A-SEC-001 - Unsigned Agent Card (CRITICAL)
 */
export declare function checkSignaturesPresent(card: AgentCard): SecurityFinding[];
/**
 * Rule 2: A2A-SEC-002 - Insecure / Rogue Cryptographic Signature (CRITICAL)
 */
export declare function checkSignatureIntegrity(card: AgentCard): SecurityFinding[];
/**
 * Rule 3: A2A-SEC-003 - Insecure Cleartext Transport (HIGH)
 */
export declare function checkTransportEncryption(card: AgentCard): SecurityFinding[];
/**
 * Rule 4: A2A-SEC-004 - SSRF & Internal Network Exposure (CRITICAL)
 */
export declare function checkSsrfExposure(card: AgentCard): SecurityFinding[];
/**
 * Rule 5: A2A-SEC-005 - Adversarial Prompt Injection & Obfuscation (HIGH)
 */
export declare function checkPromptInjectionInMetadata(card: AgentCard): SecurityFinding[];
/**
 * Rule 6: A2A-SEC-006 - Unauthenticated Dangerous Primitives (HIGH)
 */
export declare function checkUnauthenticatedDangerousSkills(card: AgentCard): SecurityFinding[];
/**
 * Rule 7: A2A-SEC-007 - Deprecated & Insecure OAuth Flows (MEDIUM)
 */
export declare function checkDeprecatedOAuthFlows(card: AgentCard): SecurityFinding[];
/**
 * Rule 8: A2A-SEC-008 - API Key Query Parameter Leakage (MEDIUM)
 */
export declare function checkApiKeyQueryParameter(card: AgentCard): SecurityFinding[];
/**
 * Rule 9: A2A-SEC-009 - Unauthenticated Extended Agent Card Escalation (HIGH)
 */
export declare function checkExtendedCardAuthentication(card: AgentCard): SecurityFinding[];
/**
 * Rule 10: A2A-SEC-010 - Protocol Specification & Schema Compliance (LOW/INFO)
 */
export declare function checkSchemaCompliance(card: AgentCard): SecurityFinding[];
/**
 * Aggregates and runs all 10 security rules against an Agent Card
 */
export declare function executeAllRules(card: AgentCard): SecurityFinding[];
//# sourceMappingURL=rules.d.ts.map