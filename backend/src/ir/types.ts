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

export type NodeKind = 'middleware' | 'handler' | 'auth' | 'route';
export type AuthEnforcement = 'hard' | 'optional' | 'conditional';


/**
 * Metadata attached to nodes for analysis
 */

export interface NodeMetadata {
  isAsync: boolean;
  referencesUser: boolean;
  fileImports: string[];
  isAuthRelated: boolean; // Populated by analysis pass
  authType?: 'entry' | 'enforcer';// Optional auth role
  enforcement?: AuthEnforcement;
  sourceLocation: SourceLocation;
}

/**
 * A node in the execution graph (middleware or handler)
 */
export interface ExecutionNode {
  id: string;
  type: NodeKind;
  name: string;
  metadata: NodeMetadata;
}


/**
 * Directed edge representing execution flow
 */
export interface Edge {
  from: string;
  to: string;
  condition: 'always' | 'true' | 'false';
}

/**
 * Source code location
 */
export interface SourceLocation {
  filePath: string;
  line: number;
}