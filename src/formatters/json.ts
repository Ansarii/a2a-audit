import { AuditReport } from '../types';

export function formatJsonReport(report: AuditReport): string {
  return JSON.stringify(report, null, 2);
}
