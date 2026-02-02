/**
 * Phase 4: Comprehensive Security Report Generator
 * 
 * Generates human-readable and machine-readable security reports
 * with risk scoring and prioritized remediation.
 */

import type {
    ExecutionGraph,
    SecurityFinding,
    ExecutiveSummary,
    RiskScore,
    Severity,
} from '../ir/types.js';
import type { AuthAnalysis } from './authPresence.js';

export interface SecurityReport {
    summary: ExecutiveSummary;
    prioritizedFindings: SecurityFinding[];
    remediationPlan: RemediationItem[];
    overallStatus: 'Secure' | 'At Risk' | 'Critical';
}

export interface RemediationItem {
    priority: 'Immediate' | 'High' | 'Medium' | 'Low';
    findingId: string;
    issue: string;
    remediation: string;
}

/**
 * Generate full security report for Phase 4
 */
export function generateSecurityReport(
    graph: ExecutionGraph,
    analysis: AuthAnalysis
): SecurityReport {
    const allFindings: SecurityFinding[] = [];
    for (const findings of analysis.allFindings.values()) {
        allFindings.push(...findings);
    }

    // Deduplicate findings if attached to multiple routes but clearly the same issue (e.g., in a shared middleware)
    const uniqueFindings = deduplicateFindings(allFindings);

    const executiveSummary = calculateExecutiveSummary(uniqueFindings, graph);
    const prioritizedFindings = sortFindingsByRisk(uniqueFindings);
    const remediationPlan = generateRemediationPlan(prioritizedFindings);

    let overallStatus: SecurityReport['overallStatus'] = 'Secure';
    if (executiveSummary.riskScore > 70 || executiveSummary.criticalIssues > 0) {
        overallStatus = 'Critical';
    } else if (executiveSummary.riskScore > 30 || executiveSummary.highIssues > 0) {
        overallStatus = 'At Risk';
    }

    return {
        summary: executiveSummary,
        prioritizedFindings,
        remediationPlan,
        overallStatus,
    };
}

/**
 * Calculate executive summary metrics
 */
function calculateExecutiveSummary(
    findings: SecurityFinding[],
    graph: ExecutionGraph
): ExecutiveSummary {
    const critical = findings.filter(f => f.severity === 'critical').length;
    const high = findings.filter(f => f.severity === 'high').length;

    // Risk score algorithm: 
    // Weighted average of top 5 most severe findings
    const sortedScores = findings.map(f => f.riskScore).sort((a, b) => b - a);
    const topScores = sortedScores.slice(0, 5);
    const avgRisk = topScores.length > 0
        ? topScores.reduce((a, b) => a + b, 0) / topScores.length
        : 0;

    let complexity: ExecutiveSummary['remediationComplexity'] = 'low';
    if (critical > 3 || findings.length > 10) complexity = 'high';
    else if (critical > 0 || high > 3) complexity = 'medium';

    return {
        riskScore: Math.round(avgRisk),
        criticalIssues: critical,
        highIssues: high,
        totalFindings: findings.length,
        remediationComplexity: complexity,
    };
}

/**
 * Sort findings by risk score descending
 */
function sortFindingsByRisk(findings: SecurityFinding[]): SecurityFinding[] {
    return [...findings].sort((a, b) => b.riskScore - a.riskScore);
}

/**
 * Prioritize remediation actions
 */
function generateRemediationPlan(findings: SecurityFinding[]): RemediationItem[] {
    return findings.map(f => {
        let priority: RemediationItem['priority'] = 'Low';
        if (f.severity === 'critical') priority = 'Immediate';
        else if (f.severity === 'high') priority = 'High';
        else if (f.severity === 'medium') priority = 'Medium';

        return {
            priority,
            findingId: f.id,
            issue: f.message,
            remediation: f.remediation || 'Consult security best practices for this issue type.',
        };
    });
}

/**
 * Deduplicate findings by type and message
 */
function deduplicateFindings(findings: SecurityFinding[]): SecurityFinding[] {
    const seen = new Set<string>();
    return findings.filter(f => {
        const key = `${f.type}-${f.message}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });
}
