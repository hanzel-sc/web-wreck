/**
 * JSON output serialization
 */

import type { ExecutionGraph } from '../ir/types.js';
import type { AuthAnalysis } from '../analyze/authPrescence.js';

export interface JsonOutput {
  summary: {
    totalRoutes: number;
    totalNodes: number;
    authNodes: number;
    unauthenticatedRoutes: number;
  };
  routes: Array<{
    id: string;
    method: string;
    path: string;
    hasAuth: boolean;
    file: string;
    line: number;
  }>;
  authNodes: string[];
  vulnerableRoutes: Array<{
    id: string;
    method: string;
    path: string;
    file: string;
    line: number;
  }>;
}

/**
 * Generate structured JSON output
 */
export function outputJson(graph: ExecutionGraph, analysis: AuthAnalysis): JsonOutput {
  const unauthSet = new Set(analysis.unauthenticatedRoutes);
  
  return {
    summary: {
      totalRoutes: graph.routes.length,
      totalNodes: graph.nodes.size,
      authNodes: analysis.authNodes.length,
      unauthenticatedRoutes: analysis.unauthenticatedRoutes.length,
    },
    routes: graph.routes.map(r => ({
      id: r.id,
      method: r.method,
      path: r.path,
      hasAuth: !unauthSet.has(r.id),
      file: r.sourceLocation.filePath,
      line: r.sourceLocation.line,
    })),
    authNodes: analysis.authNodes,
    vulnerableRoutes: graph.routes
      .filter(r => unauthSet.has(r.id))
      .map(r => ({
        id: r.id,
        method: r.method,
        path: r.path,
        file: r.sourceLocation.filePath,
        line: r.sourceLocation.line,
      })),
  };
}