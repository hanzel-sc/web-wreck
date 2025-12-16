/**
 * Intermediate Representation (IR) type definitions
 * Framework-agnostic execution graph
 */

/**
 * Main IR structure representing the entire application
 */
export interface ExecutionGraph {
  routes: Route[];
  nodes: Map<string, ExecutionNode>;
  edges: Edge[];
}

/**
 * A single route entry point
 */
export interface Route {
  id: string;
  method: string;
  path: string;
  entryNodeId: string;
  sourceLocation: SourceLocation;
}

/**
 * A node in the execution graph (middleware or handler)
 */
export interface ExecutionNode {
  id: string;
  type: 'middleware' | 'handler';
  name: string;
  metadata: NodeMetadata;
}

/**
 * Metadata attached to nodes for analysis
 */
export interface NodeMetadata {
  isAsync: boolean;
  referencesUser: boolean;
  fileImports: string[];
  isAuthRelated: boolean; // Populated by analysis pass
  sourceLocation: SourceLocation;
}

/**
 * Directed edge representing execution flow
 */
export interface Edge {
  from: string;
  to: string;
}

/**
 * Source code location
 */
export interface SourceLocation {
  filePath: string;
  line: number;
}