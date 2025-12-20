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
 * Metadata attached to nodes for analysis
 */

export type NodeKind = 'middleware' | 'handler' | 'auth' | 'route';
export type AuthEnforcement = 'hard' | 'optional' | 'conditional';

export interface NodeMetadata {
  isAsync: boolean;
  referencesUser: boolean;
  fileImports: string[];

  // Phase 3 auth semantics
  authType?: 'entry' | 'enforcer';
  enforcement?: AuthEnforcement;
  rolesChecked?: string[];

  sourceLocation: SourceLocation;
}

export interface ExecutionNode {
  id: string;
  type: NodeKind; // keep name 'type' to minimize refactors
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