/**
 * IR validation utilities
 * Ensures graph structural integrity
 * 
 * TODO: Add cycle detection when control-flow patterns are added
 * TODO: Add orphan node detection
 */

import type { ExecutionGraph } from './types.js';

/**
 * Validate execution graph structure
 */
export function validateGraph(graph: ExecutionGraph): void {
  // Ensure all routes reference valid nodes
  for (const route of graph.routes) {
    if (!graph.nodes.has(route.entryNodeId)) {
      throw new Error(`Route ${route.id} references invalid node ${route.entryNodeId}`);
    }
  }
  
  // Ensure all edges reference valid nodes
  for (const edge of graph.edges) {
    if (!graph.nodes.has(edge.from)) {
      throw new Error(`Edge references invalid 'from' node: ${edge.from}`);
    }
    if (!graph.nodes.has(edge.to)) {
      throw new Error(`Edge references invalid 'to' node: ${edge.to}`);
    }
  }
  
  // Basic sanity checks
  if (graph.routes.length === 0) {
    throw new Error('Graph has no routes');
  }
  
  if (graph.nodes.size === 0) {
    throw new Error('Graph has no nodes');
  }
}