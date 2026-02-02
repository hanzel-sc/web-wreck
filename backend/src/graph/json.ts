/**
 * JSON output serialization - Phase 3 & 4 Enhanced
 */

import type { ExecutionGraph } from '../ir/types.js';
import type { AuthAnalysis } from '../analyze/authPresence.js';

export interface JsonOutput {
  metadata: {
    version: string;
    timestamp: string;
    repository: string;
  };
  executiveSummary: {
    riskScore: number;
    criticalIssues: number;
    highIssues: number;
    totalFindings: number;
    status: string;
  };
  summary: {
    totalRoutes: number;
    totalNodes: number;
    authNodes: number;
    unauthenticatedRoutes: number;
    bypassPaths: number;
  };
  routes: Array<{
    id: string;
    method: string;
    path: string;
    hasAuth: boolean;
    riskScore: number;
    findings: Array<{
      type: string;
      category: string;
      severity: string;
      riskScore: number;
      message: string;
      remediation?: string;
      cwe?: string;
    }>;
  }>;
  remediationPlan: Array<{
    priority: string;
    issue: string;
    remediation: string;
  }>;
}

/**
 * Generate comprehensive JSON output
 */
export function outputJson(
  graph: ExecutionGraph,
  analysis: AuthAnalysis,
  report: any // SecurityReport
): JsonOutput {
  return {
    metadata: {
      version: '0.4.0',
      timestamp: new Date().toISOString(),
      repository: 'analyzed-repository',
    },
    executiveSummary: {
      riskScore: report.summary.riskScore,
      criticalIssues: report.summary.criticalIssues,
      highIssues: report.summary.highIssues,
      totalFindings: report.summary.totalFindings,
      status: report.overallStatus,
    },
    summary: {
      totalRoutes: graph.routes.length,
      totalNodes: graph.nodes.size,
      authNodes: analysis.authNodes.length,
      unauthenticatedRoutes: analysis.unauthenticated.length,
      bypassPaths: analysis.bypassPaths.length,
    },
    routes: graph.routes.map(r => {
      const findings = analysis.allFindings.get(r.id) ?? [];
      const maxRisk = findings.length > 0 ? Math.max(...findings.map(f => f.riskScore)) : 0;

      return {
        id: r.id,
        method: r.method,
        path: r.path,
        hasAuth: !analysis.unauthenticated.includes(r.id),
        riskScore: maxRisk,
        findings: findings.map(f => ({
          type: f.type,
          category: f.category,
          severity: f.severity,
          riskScore: f.riskScore,
          message: f.message,
          remediation: f.remediation,
          cwe: f.cwe,
        })),
      };
    }),
    remediationPlan: report.remediationPlan.map((rp: any) => ({
      priority: rp.priority,
      issue: rp.issue,
      remediation: rp.remediation,
    })),
  };
}

/**
 * Get route execution chain
 */
function getRouteChain(graph: ExecutionGraph, startNodeId: string): string[] {
  const visited = new Set<string>();
  const result: string[] = [];

  function dfs(nodeId: string) {
    if (visited.has(nodeId)) return;
    visited.add(nodeId);
    result.push(nodeId);

    const outgoing = graph.edges.filter(e => e.from === nodeId);
    for (const edge of outgoing) {
      dfs(edge.to);
    }
  }

  dfs(startNodeId);
  return result;
}