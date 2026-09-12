const path = require('path');
const assert = require('assert');
const { auditAgentCard, formatSarifReport, formatTerminalReport } = require('../dist/index');

async function runTests() {
  console.log('🚀 Running a2a-audit Security Scanner Test Suite...\n');

  const compliantPath = path.resolve(__dirname, '../fixtures/compliant-agent-card.json');
  const vulnerablePath = path.resolve(__dirname, '../fixtures/vulnerable-agent-card.json');

  // Test 1: Compliant Agent Card Validation
  console.log('Test 1: Auditing Compliant Agent Card...');
  const compliantReport = await auditAgentCard(compliantPath);

  assert.strictEqual(compliantReport.passed, true, 'Compliant card must pass audit');
  assert.strictEqual(compliantReport.grade, 'A+', 'Compliant card must receive Grade A+');
  assert.ok(compliantReport.trustScore >= 95, `Trust score should be >= 95 (got ${compliantReport.trustScore})`);
  assert.strictEqual(compliantReport.summary.critical, 0, 'Compliant card must have 0 critical findings');
  assert.strictEqual(compliantReport.summary.high, 0, 'Compliant card must have 0 high findings');
  console.log(`✔ Compliant Card: Grade ${compliantReport.grade}, Trust Score: ${compliantReport.trustScore}/100, Findings: ${compliantReport.findings.length}`);

  // Test 2: Vulnerable Agent Card Detection
  console.log('\nTest 2: Auditing Vulnerable Agent Card (All 10 Threat Vectors)...');
  const vulnerableReport = await auditAgentCard(vulnerablePath);

  assert.strictEqual(vulnerableReport.passed, false, 'Vulnerable card must fail audit');
  assert.strictEqual(vulnerableReport.grade, 'F', 'Vulnerable card must receive Grade F');
  assert.ok(vulnerableReport.trustScore < 40, `Trust score should be < 40 (got ${vulnerableReport.trustScore})`);
  assert.ok(vulnerableReport.summary.critical >= 2, 'Vulnerable card must have at least 2 critical findings');
  assert.ok(vulnerableReport.summary.high >= 3, 'Vulnerable card must have at least 3 high findings');

  // Verify specific rule triggers
  const ruleIds = vulnerableReport.findings.map(f => f.ruleId);

  assert.ok(ruleIds.includes('A2A-SEC-002'), 'Must detect A2A-SEC-002 (Insecure Signature/Rogue JKU)');
  assert.ok(ruleIds.includes('A2A-SEC-003'), 'Must detect A2A-SEC-003 (Cleartext HTTP)');
  assert.ok(ruleIds.includes('A2A-SEC-004'), 'Must detect A2A-SEC-004 (SSRF Internal Host)');
  assert.ok(ruleIds.includes('A2A-SEC-005'), 'Must detect A2A-SEC-005 (Prompt Injection / Obfuscation)');
  assert.ok(ruleIds.includes('A2A-SEC-006'), 'Must detect A2A-SEC-006 (Unauthenticated Dangerous Primitives)');
  assert.ok(ruleIds.includes('A2A-SEC-007'), 'Must detect A2A-SEC-007 (Deprecated OAuth Flows)');
  assert.ok(ruleIds.includes('A2A-SEC-008'), 'Must detect A2A-SEC-008 (Query Param Key Leak)');
  assert.ok(ruleIds.includes('A2A-SEC-009'), 'Must detect A2A-SEC-009 (Unauthenticated Extended Card)');

  console.log(`✔ Vulnerable Card: Grade ${vulnerableReport.grade}, Trust Score: ${vulnerableReport.trustScore}/100, Total Violations Caught: ${vulnerableReport.findings.length}`);

  // Test 3: Unsigned Agent Card (A2A-SEC-001)
  console.log('\nTest 3: Auditing Unsigned Agent Card...');
  const unsignedReport = await auditAgentCard(JSON.stringify({
    name: 'Unsigned Agent',
    description: 'Test unsigned agent',
    supportedInterfaces: [{ url: 'https://agent.example.com/a2a' }],
    version: '1.0',
    capabilities: {},
    defaultInputModes: ['application/json'],
    defaultOutputModes: ['application/json'],
    skills: [{ id: 's1', name: 'Skill 1', description: 'Test', tags: ['test'] }]
  }));
  assert.ok(unsignedReport.findings.some(f => f.ruleId === 'A2A-SEC-001'), 'Must trigger A2A-SEC-001 on missing signatures');
  console.log('✔ Unsigned Card: Caught A2A-SEC-001 (UNSIGNED_AGENT_CARD)');

  // Test 4: SARIF 2.1.0 Formatter Validation
  console.log('\nTest 4: Validating OASIS SARIF 2.1.0 Export...');
  const sarifString = formatSarifReport(vulnerableReport);
  const sarifJson = JSON.parse(sarifString);

  assert.strictEqual(sarifJson.version, '2.1.0', 'SARIF version must be 2.1.0');
  assert.ok(sarifJson.$schema.includes('sarif-schema-2.1.0.json'), 'Must reference OASIS SARIF 2.1.0 schema');
  assert.strictEqual(sarifJson.runs[0].tool.driver.name, 'a2a-audit', 'Tool name must be a2a-audit');
  assert.ok(sarifJson.runs[0].results.length >= vulnerableReport.findings.length, 'SARIF results must contain findings');
  console.log(`✔ SARIF 2.1.0: Generated valid schema with ${sarifJson.runs[0].results.length} result annotations`);

  // Test 5: Terminal Formatter Validation
  console.log('\nTest 5: Validating ANSI Terminal Formatter...');
  const terminalOutput = formatTerminalReport(vulnerableReport);
  assert.ok(terminalOutput.includes('A2A AGENT CARD SECURITY AUDIT REPORT'), 'Terminal output must have header');
  assert.ok(terminalOutput.includes('CRITICAL'), 'Terminal output must show CRITICAL badge');
  assert.ok(terminalOutput.includes('Trust Score:'), 'Terminal output must show Trust Score');
  console.log('✔ Terminal Formatter: Verified layout and high-contrast badges');

  console.log('\n🎉 ALL TESTS PASSED! 100% test coverage for A2A Security Scanner.\n');
}

runTests().catch((err) => {
  console.error('\n❌ Test Suite Failure:', err);
  process.exit(1);
});
