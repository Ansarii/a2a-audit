"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.formatSarifReport = formatSarifReport;
function mapSeverityToSarifLevel(severity) {
    switch (severity) {
        case 'CRITICAL':
        case 'HIGH':
            return 'error';
        case 'MEDIUM':
            return 'warning';
        case 'LOW':
        case 'INFO':
        default:
            return 'note';
    }
}
function formatSarifReport(report) {
    // Collect unique rules from findings
    const rulesMap = new Map();
    report.findings.forEach((f) => {
        if (!rulesMap.has(f.ruleId)) {
            rulesMap.set(f.ruleId, f);
        }
    });
    const sarifRules = Array.from(rulesMap.values()).map((f) => ({
        id: f.ruleId,
        name: f.ruleName,
        shortDescription: {
            text: f.ruleName.replace(/_/g, ' ')
        },
        fullDescription: {
            text: f.message
        },
        help: {
            text: `Remediation: ${f.remediation}`
        },
        defaultConfiguration: {
            level: mapSeverityToSarifLevel(f.severity)
        },
        properties: {
            cwe: f.cwe,
            aiTechTaxonomy: f.aiTechTaxonomy
        }
    }));
    const sarifResults = report.findings.map((f) => ({
        ruleId: f.ruleId,
        ruleIndex: sarifRules.findIndex((r) => r.id === f.ruleId),
        level: mapSeverityToSarifLevel(f.severity),
        message: {
            text: `${f.message} (Field: ${f.field}). Remediation: ${f.remediation}`
        },
        locations: [
            {
                physicalLocation: {
                    artifactLocation: {
                        uri: report.target.startsWith('http') ? report.target : `file://${report.target}`
                    },
                    region: {
                        startLine: 1,
                        startColumn: 1
                    }
                }
            }
        ]
    }));
    const sarifDocument = {
        $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        version: '2.1.0',
        runs: [
            {
                tool: {
                    driver: {
                        name: 'a2a-audit',
                        version: '1.0.0',
                        informationUri: 'https://github.com/Ansarii/a2a-audit',
                        rules: sarifRules
                    }
                },
                results: sarifResults
            }
        ]
    };
    return JSON.stringify(sarifDocument, null, 2);
}
//# sourceMappingURL=sarif.js.map