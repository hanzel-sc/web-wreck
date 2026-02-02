/**
 * Phase 4: Security Findings Management
 * Associates security findings with graph nodes and routes
 */

import type {
  ExecutionGraph,
  SecurityFinding,
  Severity,
  FindingType,
} from '../ir/types.js';
import type { AuthAnalysis } from './authPresence.js';

export interface FindingReport {
  summary: FindingSummary;
  byRoute: Map<string, RouteFinding>;
  byNode: Map<string, NodeFinding>;
  bySeverity: Map<Severity, SecurityFinding[]>;
  byType: Map<FindingType, SecurityFinding[]>;
}

export interface FindingSummary {
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  avgRiskScore: number;
  affectedRoutes: number;
  affectedNodes: number;
}

export interface RouteFinding {
  routeId: string;
  method: string;
  path: string;
  findings: SecurityFinding[];
  maxSeverity: Severity;
  maxRiskScore: number;
  file: string;
  line: number;
}

export interface NodeFinding {
  nodeId: string;
  nodeName: string;
  nodeType: string;
  findings: SecurityFinding[];
  file: string;
  line: number;
}

/**
 * Generate comprehensive finding report from analysis
 */
export function generateFindingReport(
  graph: ExecutionGraph,
  analysis: AuthAnalysis
): FindingReport {
  const byRoute = new Map<string, RouteFinding>();
  const byNode = new Map<string, NodeFinding>();
  const bySeverity = new Map<Severity, SecurityFinding[]>();
  const byType = new Map<FindingType, SecurityFinding[]>();

  // Initialize severity buckets
  (['critical', 'high', 'medium', 'low', 'info'] as Severity[]).forEach(s => {
    bySeverity.set(s, []);
  });

  // Process findings by route
  for (const [routeId, findings] of analysis.allFindings) {
    const route = graph.routes.find(r => r.id === routeId);
    if (!route) continue;

    // Determine max severity and risk score
    const severities: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
    let maxRiskScore = 0;
    const maxSeverity = findings.reduce((max, f) => {
      if (f.riskScore > maxRiskScore) maxRiskScore = f.riskScore;
      return severities.indexOf(f.severity) > severities.indexOf(max)
        ? f.severity
        : max;
    }, 'info' as Severity);

    byRoute.set(routeId, {
      routeId,
      method: route.method,
      path: route.path,
      findings,
      maxSeverity,
      maxRiskScore,
      file: route.sourceLocation.filePath,
      line: route.sourceLocation.line,
    });

    // Categorize by severity and type
    for (const finding of findings) {
      const severityBucket = bySeverity.get(finding.severity) ?? [];
      severityBucket.push(finding);
      bySeverity.set(finding.severity, severityBucket);

      const typeBucket = byType.get(finding.type) ?? [];
      typeBucket.push(finding);
      byType.set(finding.type, typeBucket);
    }
  }

  // Associate findings with nodes
  for (const route of graph.routes) {
    const routeFindings = byRoute.get(route.id);
    if (!routeFindings) continue;

    const chain = getOrderedExecutionChain(graph, route.entryNodeId);
    for (const node of chain) {
      // Add relevant findings to this node
      const nodeFindings = routeFindings.findings.filter(f =>
        isRelevantToNode(f, node.type, node.name)
      );

      if (nodeFindings.length > 0) {
        const existing = byNode.get(node.id) ?? {
          nodeId: node.id,
          nodeName: node.name,
          nodeType: node.type,
          findings: [],
          file: node.metadata.sourceLocation.filePath,
          line: node.metadata.sourceLocation.line,
        };

        existing.findings.push(...nodeFindings);
        byNode.set(node.id, existing);
      }
    }
  }

  // Generate summary
  const summary = generateSummary(bySeverity, byRoute, byNode);

  return {
    summary,
    byRoute,
    byNode,
    bySeverity,
    byType,
  };
}

/**
 * Generate summary statistics
 */
function generateSummary(
  bySeverity: Map<Severity, SecurityFinding[]>,
  byRoute: Map<string, RouteFinding>,
  byNode: Map<string, NodeFinding>
): FindingSummary {
  const allFindings: SecurityFinding[] = [];
  bySeverity.forEach(bucket => allFindings.push(...bucket));

  const avgRisk = allFindings.length > 0
    ? allFindings.reduce((a, b) => a + b.riskScore, 0) / allFindings.length
    : 0;

  return {
    totalFindings: allFindings.length,
    critical: bySeverity.get('critical')?.length ?? 0,
    high: bySeverity.get('high')?.length ?? 0,
    medium: bySeverity.get('medium')?.length ?? 0,
    low: bySeverity.get('low')?.length ?? 0,
    info: bySeverity.get('info')?.length ?? 0,
    avgRiskScore: Math.round(avgRisk),
    affectedRoutes: byRoute.size,
    affectedNodes: byNode.size,
  };
}

/**
 * Get ordered execution chain via traversal
 */
function getOrderedExecutionChain(graph: ExecutionGraph, startNodeId: string): any[] {
  const visited = new Set<string>();
  const result: any[] = [];

  function dfs(nodeId: string) {
    if (visited.has(nodeId)) return;
    visited.add(nodeId);
    const node = graph.nodes.get(nodeId);
    if (node) result.push(node);

    // Simplistic DFS for now as build.ts produces linear chains mostly
    const outgoing = graph.edges.filter(e => e.from === nodeId);
    for (const edge of outgoing) dfs(edge.to);
  }

  dfs(startNodeId);
  return result;
}

/**
 * Determine if a finding is relevant to a specific node
 */
function isRelevantToNode(
  finding: SecurityFinding,
  nodeType: string,
  nodeName: string
): boolean {
  // Auth-related findings are relevant to auth nodes
  if (
    nodeType === 'auth' &&
    (finding.type.includes('auth') ||
      finding.type.includes('jwt') ||
      finding.type.includes('rbac'))
  ) {
    return true;
  }

  // Handler-related findings
  if (
    nodeType === 'handler' &&
    (finding.type === 'auth-after-handler' || finding.type === 'missing-rbac')
  ) {
    return true;
  }

  // Check if finding message mentions the node
  if (finding.message.includes(nodeName)) {
    return true;
  }

  return false;
}

/**
 * Export findings in markdown format
 */
export function exportFindingsMarkdown(report: FindingReport): string {
  const lines: string[] = [];

  lines.push('# Security Analysis Report');
  lines.push('');
  lines.push('## Summary');
  lines.push('');
  lines.push(`- **Total Findings**: ${report.summary.totalFindings}`);
  lines.push(`- **Critical**: ${report.summary.critical}`);
  lines.push(`- **High**: ${report.summary.high}`);
  lines.push(`- **Medium**: ${report.summary.medium}`);
  lines.push(`- **Low**: ${report.summary.low}`);
  lines.push(`- **Affected Routes**: ${report.summary.affectedRoutes}`);
  lines.push('');

  // Findings by severity
  lines.push('## Findings by Severity');
  lines.push('');

  for (const severity of ['critical', 'high', 'medium', 'low'] as Severity[]) {
    const findings = report.bySeverity.get(severity) ?? [];
    if (findings.length === 0) continue;

    lines.push(`### ${severity.toUpperCase()} (${findings.length})`);
    lines.push('');

    for (const finding of findings) {
      lines.push(`- **${finding.type}**: ${finding.message}`);
      if (finding.remediation) {
        lines.push(`  - *Remediation*: ${finding.remediation}`);
      }
      if (finding.cwe) {
        lines.push(`  - *CWE*: ${finding.cwe}`);
      }
      lines.push('');
    }
  }

  // Findings by route
  lines.push('## Findings by Route');
  lines.push('');

  for (const [_, routeFinding] of report.byRoute) {
    lines.push(
      `### ${routeFinding.method} ${routeFinding.path} [${routeFinding.maxSeverity.toUpperCase()}]`
    );
    lines.push('');
    lines.push(`*Location*: ${routeFinding.file}:${routeFinding.line}`);
    lines.push('');

    for (const finding of routeFinding.findings) {
      lines.push(`- [${finding.severity.toUpperCase()}] ${finding.message}`);
      if (finding.remediation) {
        lines.push(`  - ${finding.remediation}`);
      }
    }
    lines.push('');
  }

  return lines.join('\n');
}