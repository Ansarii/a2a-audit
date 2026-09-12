"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.calculateScoreAndGrade = calculateScoreAndGrade;
function calculateScoreAndGrade(findings, strictMode = false) {
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
    let grade = 'F';
    if (critical > 0) {
        grade = 'F';
    }
    else if (trustScore >= 95 && high === 0) {
        grade = 'A+';
    }
    else if (trustScore >= 85 && high === 0) {
        grade = 'A';
    }
    else if (trustScore >= 70 && high <= 1) {
        grade = 'B';
    }
    else if (trustScore >= 50) {
        grade = 'C';
    }
    else if (trustScore >= 40) {
        grade = 'D';
    }
    else {
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
//# sourceMappingURL=scoring.js.map