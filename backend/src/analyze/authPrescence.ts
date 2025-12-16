/**
 * Authentication presence analysis
 * Heuristically identifies auth-related middleware and unprotected routes
 *
 * NOTE:
 * - This pass annotates node metadata (isAuthRelated)
 * - It does NOT modify graph structure
 */

import type { ExecutionGraph } from '../ir/types.js';

export interface AuthAnalysis {
  authNodes: string[];
  unauthenticatedRoutes: string[];
}

const AUTH_KEYWORDS = [
  'auth',
  'verify',
  'token',
  'jwt',
  'passport',
  'authorize',
  'authenticate',
];

const AUTH_LIBRARIES = [
  'jsonwebtoken',
  'passport',
  'express-jwt',
  'jwt-simple',
  '@auth0',
];

export function analyzeAuthPresence(graph: ExecutionGraph): AuthAnalysis {
  const authNodes = new Set<string>();

  // Precompute adjacency list once
  const adjacency = buildAdjacency(graph);

  // Identify auth-related nodes
  for (const [nodeId, node] of graph.nodes) {
    if (
      isAuthRelated(
        node.name,
        node.metadata.fileImports,
        node.metadata.referencesUser
      )
    ) {
      authNodes.add(nodeId);
      node.metadata.isAuthRelated = true; // annotation
    }
  }

  // Identify unauthenticated routes
  const unauthenticatedRoutes: string[] = [];

  for (const route of graph.routes) {
    const chain = getExecutionChain(adjacency, route.entryNodeId);
    const hasAuth = chain.some(nodeId => authNodes.has(nodeId));

    if (!hasAuth) {
      unauthenticatedRoutes.push(route.id);
    }
  }

  return {
    authNodes: Array.from(authNodes),
    unauthenticatedRoutes,
  };
}

/**
 * Determine if a node is auth-related using heuristics
 */
function isAuthRelated(
  name: string,
  fileImports: string[],
  referencesUser: boolean
): boolean {
  const lowerName = name.toLowerCase();

  // Name-based heuristic
  if (AUTH_KEYWORDS.some(kw => lowerName.includes(kw))) {
    return true;
  }

  // req.user heuristic
  if (referencesUser) {
    return true;
  }

  // Import-based heuristic (coarse, v0)
  if (
    fileImports.some(imp =>
      AUTH_LIBRARIES.some(lib => imp.includes(lib))
    )
  ) {
    return true;
  }

  return false;
}

/**
 * Build adjacency list for graph traversal
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
 * BFS traversal to collect execution chain
 */
function getExecutionChain(
  adjacency: Map<string, string[]>,
  startNodeId: string
): string[] {
  const visited = new Set<string>();
  const queue: string[] = [startNodeId];

  while (queue.length > 0) {
    const nodeId = queue.shift()!;
    if (visited.has(nodeId)) continue;

    visited.add(nodeId);

    const neighbors = adjacency.get(nodeId) ?? [];
    for (const next of neighbors) {
      queue.push(next);
    }
  }

  return Array.from(visited);
}
