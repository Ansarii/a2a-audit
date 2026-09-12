import { AuditReport, SecurityFinding, SeverityLevel } from '../types';

export interface ScoreResult {
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
}

export function calculateScoreAndGrade(findings: SecurityFinding[], strictMode = false): ScoreResult {
  let critical = 0;
  let high = 0;
  let medium = 0;
  let low = 0;
  let info = 0;

  let totalDeductions = 0;

  for (const finding of findings) {
    switch (finding.severity) {
      case 'CRITICAL':
        critical++;
        totalDeductions += 40;
        break;
      case 'HIGH':
        high++;
        totalDeductions += 25;
        break;
      case 'MEDIUM':
        medium++;
        totalDeductions += 10;
        break;
      case 'LOW':
        low++;
        totalDeductions += 5;
        break;
      case 'INFO':
        info++;
        break;
    }
  }

  const trustScore = Math.max(0, Math.min(100, 100 - totalDeductions));

  let grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F' = 'F';

  if (critical > 0) {
    grade = 'F';
  } else if (trustScore >= 95 && high === 0) {
    grade = 'A+';
  } else if (trustScore >= 85 && high === 0) {
    grade = 'A';
  } else if (trustScore >= 70 && high <= 1) {
    grade = 'B';
  } else if (trustScore >= 50) {
    grade = 'C';
  } else if (trustScore >= 40) {
    grade = 'D';
  } else {
    grade = 'F';
  }

  const passed = strictMode
    ? critical === 0 && high === 0 && medium === 0
    : critical === 0 && high === 0;

  return {
    trustScore,
    grade,
    passed,
    summary: {
      total: findings.length,
      critical,
      high,
      medium,
      low,
      info
    }
  };
}
