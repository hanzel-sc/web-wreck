/**
 * Phase 3 Authentication & Authorization Analysis
 *
 * Analyzes execution chains for:
 * - Missing authentication
 * - Incorrect auth ordering
 * - Optional / conditional auth
 * - Missing RBAC on privileged routes
 *
 * This module DOES NOT:
 * - Use string heuristics
 * - Modify graph structure
 * - Infer auth from imports
 */

import type {
  ExecutionGraph,
  ExecutionNode,
  Route
} from '../ir/types.js';

export interface AuthAnalysis {
  unauthenticated: string[];
  authAfterHandler: string[];
  optionalAuth: string[];
  conditionalAuth: string[];
  missingRBAC: string[];
  authNodes: string[];
}

export function analyzeAuthPresence(graph: ExecutionGraph): AuthAnalysis {
  const findings: AuthAnalysis = {
    unauthenticated: [],
    authAfterHandler: [],
    optionalAuth: [],
    conditionalAuth: [],
    missingRBAC: [],
    authNodes: [],
  };

  const adjacency = buildAdjacency(graph);

  for (const route of graph.routes) {
    const chain = getOrderedExecutionChain(
      graph,
      adjacency,
      route.entryNodeId
    );

    analyzeRouteChain(route, chain, findings);
  }

  return findings;
}

/* ------------------------------------------------------------------ */
/* Route Analysis                                                      */
/* ------------------------------------------------------------------ */

function analyzeRouteChain(
  route: Route,
  chain: ExecutionNode[],
  findings: AuthAnalysis
) {
  const authNodes = chain.filter(n => n.type === 'auth');
  const handlerIndex = chain.findIndex(n => n.type === 'handler');

  // No auth anywhere → unauthenticated route
  if (authNodes.length === 0) {
    findings.unauthenticated.push(route.id);
    return;
  }

  for (const authNode of authNodes) {
    const authIndex = chain.indexOf(authNode);

    // Auth runs after handler → dead auth
    if (handlerIndex !== -1 && authIndex > handlerIndex) {
      findings.authAfterHandler.push(route.id);
    }

    // Optional auth (does not block)
    if (authNode.metadata.enforcement === 'optional') {
      findings.optionalAuth.push(route.id);
    }

    // Conditional auth (if (req.user))
    if (authNode.metadata.enforcement === 'conditional') {
      findings.conditionalAuth.push(route.id);
    }

    // RBAC check for privileged routes
    if (
      isPrivilegedRoute(route) &&
      (!authNode.metadata.rolesChecked ||
        authNode.metadata.rolesChecked.length === 0)
    ) {
      findings.missingRBAC.push(route.id);
    }
  }
}

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

function isPrivilegedRoute(route: Route): boolean {
  const path = route.path.toLowerCase();
  return (
    path.includes('admin') ||
    path.includes('internal') ||
    path.includes('manage')
  );
}

/**
 * Build adjacency list (directed)
 */
function buildAdjacency(graph: ExecutionGraph): Map<string, string[]> {
  const adjacency = new Map<string, string[]>();

  for (const [nodeId] of graph.nodes) {
    adjacency.set(nodeId, []);
  }

  for (const edge of graph.edges) {
    adjacency.get(edge.from)?.push(edge.to);
  }

  return adjacency;
}

/**
 * Ordered DFS traversal
 * Preserves execution order (critical for auth ordering analysis)
 */
function getOrderedExecutionChain(
  graph: ExecutionGraph,
  adjacency: Map<string, string[]>,
  startNodeId: string
): ExecutionNode[] {
  const visited = new Set<string>();
  const result: ExecutionNode[] = [];

  function dfs(nodeId: string) {
    if (visited.has(nodeId)) return;
    visited.add(nodeId);

    const node = graph.nodes.get(nodeId);
    if (node) {
      result.push(node);
    }

    const neighbors = adjacency.get(nodeId) ?? [];
    for (const next of neighbors) {
      dfs(next);
    }
  }

  dfs(startNodeId);
  return result;
}
