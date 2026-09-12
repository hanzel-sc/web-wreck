/**
 * Shared graph utilities
 * Common DFS and adjacency operations used across analysis and output modules.
 * 
 * Previously duplicated across authPresence.ts, findings.ts, and visualize.ts.
 */

import type { ExecutionGraph, ExecutionNode } from '../ir/types.js';

/**
 * Build adjacency list from execution graph edges
 */
export function buildAdjacency(graph: ExecutionGraph): Map<string, string[]> {
  const adjacency = new Map<string, string[]>();
  for (const [nodeId] of graph.nodes) {
    adjacency.set(nodeId, []);
  }
  for (const edge of graph.edges) {
    const neighbors = adjacency.get(edge.from) ?? [];
    neighbors.push(edge.to);
    adjacency.set(edge.from, neighbors);
  }
  return adjacency;
}

/**
 * Get ordered execution chain via DFS traversal from a starting node
 */
export function getOrderedExecutionChain(
  graph: ExecutionGraph,
  adjacency: Map<string, string[]>,
  startNodeId: string
): ExecutionNode[] {
  const visited = new Set<string>();
  const result: ExecutionNode[] = [];

  function dfs(nodeId: string): void {
    if (visited.has(nodeId)) return;
    visited.add(nodeId);
    const node = graph.nodes.get(nodeId);
    if (node) result.push(node);
    const neighbors = adjacency.get(nodeId) ?? [];
    for (const next of neighbors) dfs(next);
  }

  dfs(startNodeId);
  return result;
}
