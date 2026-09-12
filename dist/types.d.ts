/**
 * Agent2Agent (A2A) Protocol & DevSecOps Type Definitions
 * Derived from the official Linux Foundation & Google Cloud A2A specification (a2a.proto)
 */
export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export interface AgentInterface {
    url: string;
    protocolBinding?: string;
    protocolVersion?: string;
    tenant?: string;
}
export interface AgentProvider {
    organization: string;
    url: string;
}
export interface AgentCapabilities {
    streaming?: boolean;
    pushNotifications?: boolean;
    extendedAgentCard?: boolean;
    extensions?: any[];
    [key: string]: any;
}
export interface APIKeySecurityScheme {
    name: string;
    location: 'query' | 'header' | 'cookie';
    description?: string;
}
export interface HTTPAuthSecurityScheme {
    scheme: string;
    bearerFormat?: string;
    description?: string;
}
export interface OAuthFlows {
    authorizationCode?: any;
    authorization_code?: any;
    clientCredentials?: any;
    client_credentials?: any;
    implicit?: any;
    password?: any;
    deviceCode?: any;
    device_code?: any;
}
export interface OAuth2SecurityScheme {
    flows: OAuthFlows;
    oauth2MetadataUrl?: string;
    oauth2_metadata_url?: string;
    description?: string;
}
export interface OpenIdConnectSecurityScheme {
    openIdConnectUrl?: string;
    open_id_connect_url?: string;
    description?: string;
}
export interface MutualTlsSecurityScheme {
    description?: string;
}
export interface SecurityScheme {
    apiKeySecurityScheme?: APIKeySecurityScheme;
    api_key_security_scheme?: APIKeySecurityScheme;
    httpAuthSecurityScheme?: HTTPAuthSecurityScheme;
    http_auth_security_scheme?: HTTPAuthSecurityScheme;
    oauth2SecurityScheme?: OAuth2SecurityScheme;
    oauth2_security_scheme?: OAuth2SecurityScheme;
    openIdConnectSecurityScheme?: OpenIdConnectSecurityScheme;
    open_id_connect_security_scheme?: OpenIdConnectSecurityScheme;
    mtlsSecurityScheme?: MutualTlsSecurityScheme;
    mtls_security_scheme?: MutualTlsSecurityScheme;
    [key: string]: any;
}
export interface SecurityRequirement {
    schemes: Record<string, {
        list: string[];
    } | string[]>;
}
export interface AgentSkill {
    id: string;
    name: string;
    description: string;
    tags: string[];
    examples?: string[];
    inputModes?: string[];
    input_modes?: string[];
    outputModes?: string[];
    output_modes?: string[];
    securityRequirements?: SecurityRequirement[];
    security_requirements?: SecurityRequirement[];
    [key: string]: any;
}
export interface AgentCardSignature {
    protected: string;
    signature: string;
    header?: Record<string, any>;
}
export interface AgentCard {
    name: string;
    description: string;
    supportedInterfaces: AgentInterface[];
    supported_interfaces?: AgentInterface[];
    provider?: AgentProvider;
    version: string;
    documentationUrl?: string;
    documentation_url?: string;
    iconUrl?: string;
    icon_url?: string;
    capabilities: AgentCapabilities;
    securitySchemes?: Record<string, SecurityScheme>;
    security_schemes?: Record<string, SecurityScheme>;
    securityRequirements?: SecurityRequirement[];
    security_requirements?: SecurityRequirement[];
    defaultInputModes: string[];
    default_input_modes?: string[];
    defaultOutputModes: string[];
    default_output_modes?: string[];
    skills: AgentSkill[];
    signatures?: AgentCardSignature[];
    [key: string]: any;
}
export interface SecurityFinding {
    ruleId: string;
    ruleName: string;
    severity: SeverityLevel;
    message: string;
    field: string;
    value?: any;
    remediation: string;
    cwe?: string;
    aiTechTaxonomy?: string;
}
export interface AuditReport {
    target: string;
    scanTimestamp: string;
    trustScore: number;
    grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
    passed: boolean;
    summary: {
        total: number;
        critical: number;
        high: number;
        medium: number;
        low: number;
        info: number;
    };
    agentMetadata: {
        name?: string;
        version?: string;
        provider?: string;
        skillsCount: number;
        interfacesCount: number;
    };
    findings: SecurityFinding[];
}
export interface ScanOptions {
    failOn?: SeverityLevel;
    strict?: boolean;
    timeoutMs?: number;
}
//# sourceMappingURL=types.d.ts.map