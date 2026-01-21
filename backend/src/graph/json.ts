/**
 * JSON output serialization - Phase 3 & 4 Enhanced
 */

import type { ExecutionGraph } from '../ir/types.js';
import type { AuthAnalysis } from '../analyze/authPrescence.js';

export interface JsonOutput {
  metadata: {
    version: string;
    timestamp: string;
    repository: string;
  };
  summary: {
    totalRoutes: number;
    totalNodes: number;
    authNodes: number;
    
    // Phase 3: Enhanced metrics
    unauthenticatedRoutes: number;
    authAfterHandler: number;
    conditionalAuth: number;
    missingRBAC: number;
    missingJWTVerification: number;
    weakJWTValidation: number;
    bypassPaths: number;
  };
  routes: Array<{
    id: string;
    method: string;
    path: string;
    hasAuth: boolean;
    authType?: string;
    enforcement?: string;
    file: string;
    line: number;
    
    // Phase 4: Findings
    findings: Array<{
      type: string;
      severity: string;
      message: string;
      remediation?: string;
      cwe?: string;
    }>;
  }>;
  nodes: Array<{
    id: string;
    name: string;
    type: string;
    authType?: string;
    enforcement?: string;
    hasJWTVerification: boolean;
    hasRoleValidation: boolean;
    callsNext: boolean;
    hasErrorHandling: boolean;
  }>;
  vulnerableRoutes: Array<{
    id: string;
    method: string;
    path: string;
    file: string;
    line: number;
    vulnerabilityType: string;
    severity: string;
  }>;
  bypassPaths: Array<{
    routeId: string;
    method: string;
    path: string;
    bypassType: string;
    description: string;
  }>;
}

/**
 * Generate comprehensive JSON output
 */
export function outputJson(
  graph: ExecutionGraph,
  analysis: AuthAnalysis
): JsonOutput {
  const unauthSet = new Set(analysis.unauthenticated);

  return {
    metadata: {
      version: '0.3.0',
      timestamp: new Date().toISOString(),
      repository: 'analyzed-repository',
    },
    summary: {
      totalRoutes: graph.routes.length,
      totalNodes: graph.nodes.size,
      authNodes: analysis.authNodes.length,
      unauthenticatedRoutes: analysis.unauthenticated.length,
      authAfterHandler: analysis.authAfterHandler.length,
      conditionalAuth: analysis.conditionalAuth.length,
      missingRBAC: analysis.missingRBAC.length,
      missingJWTVerification: analysis.missingJWTVerification.length,
      weakJWTValidation: analysis.weakJWTValidation.length,
      bypassPaths: analysis.bypassPaths.length,
    },
    routes: graph.routes.map(r => {
      const findings = analysis.allFindings.get(r.id) ?? [];
      const chain = getRouteChain(graph, r.entryNodeId);
      const firstAuthNode = chain.find(nodeId => {
        const node = graph.nodes.get(nodeId);
        return node?.type === 'auth';
      });
      
      const authNode = firstAuthNode ? graph.nodes.get(firstAuthNode) : null;

      return {
        id: r.id,
        method: r.method,
        path: r.path,
        hasAuth: !unauthSet.has(r.id),
        authType: authNode?.metadata.authType,
        enforcement: authNode?.metadata.enforcement,
        file: r.sourceLocation.filePath,
        line: r.sourceLocation.line,
        findings: findings.map(f => ({
          type: f.type,
          severity: f.severity,
          message: f.message,
          remediation: f.remediation,
          cwe: f.cwe,
        })),
      };
    }),
    nodes: Array.from(graph.nodes.values()).map(n => ({
      id: n.id,
      name: n.name,
      type: n.type,
      authType: n.metadata.authType,
      enforcement: n.metadata.enforcement,
      hasJWTVerification: n.metadata.hasJWTVerification,
      hasRoleValidation: n.metadata.hasRoleValidation,
      callsNext: n.metadata.callsNext,
      hasErrorHandling: n.metadata.hasErrorHandling,
    })),
    vulnerableRoutes: [
      ...analysis.unauthenticated.map(id => {
        const route = graph.routes.find(r => r.id === id);
        return route ? {
          id,
          method: route.method,
          path: route.path,
          file: route.sourceLocation.filePath,
          line: route.sourceLocation.line,
          vulnerabilityType: 'missing-authentication',
          severity: 'critical',
        } : null;
      }),
      ...analysis.authAfterHandler.map(id => {
        const route = graph.routes.find(r => r.id === id);
        return route ? {
          id,
          method: route.method,
          path: route.path,
          file: route.sourceLocation.filePath,
          line: route.sourceLocation.line,
          vulnerabilityType: 'auth-after-handler',
          severity: 'critical',
        } : null;
      }),
      ...analysis.missingRBAC.map(id => {
        const route = graph.routes.find(r => r.id === id);
        return route ? {
          id,
          method: route.method,
          path: route.path,
          file: route.sourceLocation.filePath,
          line: route.sourceLocation.line,
          vulnerabilityType: 'missing-rbac',
          severity: 'critical',
        } : null;
      }),
    ].filter(Boolean) as any,
    bypassPaths: analysis.bypassPaths.map(bp => {
      const route = graph.routes.find(r => r.id === bp.routeId);
      return {
        routeId: bp.routeId,
        method: route?.method ?? 'UNKNOWN',
        path: route?.path ?? 'unknown',
        bypassType: bp.bypassType,
        description: bp.description,
      };
    }),
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