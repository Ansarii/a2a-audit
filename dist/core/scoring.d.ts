import { SecurityFinding } from '../types';
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
export declare function calculateScoreAndGrade(findings: SecurityFinding[], strictMode?: boolean): ScoreResult;
//# sourceMappingURL=scoring.d.ts.map