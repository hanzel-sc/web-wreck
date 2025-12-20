/**
 * Mermaid diagram generation for visualization
 * Generates flowchart showing route execution chains
 */

import type { ExecutionGraph } from '../ir/types.js';
import type { AuthAnalysis } from '../analyze/authPrescence.js';

/**
 * Generate Mermaid flowchart diagram
 */
export function outputMermaid(graph: ExecutionGraph, analysis: AuthAnalysis): string {
  const lines: string[] = [];
  const authSet = new Set(analysis.authNodes);
  const unauthRoutes = new Set(analysis.unauthenticated);
  
  lines.push('graph TD');
  
  // Define route entry nodes
  for (const route of graph.routes) {
    const isVulnerable = unauthRoutes.has(route.id);
    const style = isVulnerable ? ':::vulnerable' : ':::safe';
    const label = `${route.method} ${route.path}`;
    lines.push(`  ${route.id}["${label}"]${style}`);
  }
  
  // Define execution nodes
  for (const [nodeId, node] of graph.nodes) {
    const isAuth = authSet.has(nodeId);
    const style = isAuth ? ':::auth' : ':::normal';
    const shape = node.type === 'handler' ? '{{' : '[';
    const shapeEnd = node.type === 'handler' ? '}}' : ']';
    lines.push(`  ${nodeId}${shape}"${node.name}"${shapeEnd}${style}`);
  }
  
  // Connect routes to their entry nodes
  for (const route of graph.routes) {
    lines.push(`  ${route.id} --> ${route.entryNodeId}`);
  }
  
  // Add execution flow edges
  for (const edge of graph.edges) {
    lines.push(`  ${edge.from} --> ${edge.to}`);
  }
  
  // Add style definitions
  lines.push('');
  lines.push('  classDef vulnerable fill:#ff6b6b,stroke:#c92a2a,stroke-width:2px');
  lines.push('  classDef safe fill:#51cf66,stroke:#2b8a3e,stroke-width:2px');
  lines.push('  classDef auth fill:#ffd43b,stroke:#fab005,stroke-width:2px');
  lines.push('  classDef normal fill:#74c0fc,stroke:#1864ab,stroke-width:1px');
  
  return lines.join('\n');
}

/**
 * Generate simplified Mermaid output for small graphs
 */
export function outputMermaidSimple(graph: ExecutionGraph): string {
  const lines: string[] = [];
  
  lines.push('graph LR');
  
  for (const route of graph.routes) {
    lines.push(`  ${route.id}["${route.method} ${route.path}"]`);
  }
  
  return lines.join('\n');
}