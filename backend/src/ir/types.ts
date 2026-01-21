/**
 * Intermediate Representation (IR) - Phase 3 Enhanced
 * Framework-agnostic execution graph with auth semantics
 */

/**
 * Main IR structure
 */
export interface ExecutionGraph {
  routes: Route[];
  nodes: Map<string, ExecutionNode>;
  edges: Edge[];
}

/**
 * Route entry point
 */
export interface Route {
  id: string;
  method: string;
  path: string;
  entryNodeId: string;
  sourceLocation: SourceLocation;
}

/**
 * Phase 3: Node classification
 */
export type NodeKind = 'middleware' | 'handler' | 'auth';

/**
 * Phase 3: Authentication enforcement modes
 */
export type AuthEnforcement = 'hard' | 'soft' | 'conditional' | 'none';

/**
 * Phase 3: Auth middleware classification
 */
export type AuthType = 
  | 'jwt-verification'    // Validates JWT tokens
  | 'session-check'       // Checks session existence
  | 'api-key'            // Validates API keys
  | 'basic-auth'         // HTTP Basic Auth
  | 'oauth'              // OAuth flow
  | 'custom'             // Custom auth logic
  | 'unknown';           // Detected but type unclear

/**
 * Phase 3 & 4: Enhanced node metadata
 */
export interface NodeMetadata {
  // Basic info
  isAsync: boolean;
  referencesUser: boolean;
  fileImports: string[];
  sourceLocation: SourceLocation;
  
  // Phase 3: Auth classification
  authType?: AuthType;
  enforcement?: AuthEnforcement;
  
  // Phase 3: RBAC
  rolesChecked?: string[];
  hasRoleValidation: boolean;
  
  // Phase 3: JWT specifics
  hasJWTVerification: boolean;
  jwtVerifyMethod?: string | null;
  
  // Phase 3: Middleware behavior
  callsNext: boolean;
  hasErrorHandling: boolean;
  conditionalAuth: boolean;
  
  // Phase 4: Security findings
  findings: SecurityFinding[];
}

/**
 * Execution node with enhanced metadata
 */
export interface ExecutionNode {
  id: string;
  type: NodeKind;
  name: string;
  metadata: NodeMetadata;
}

/**
 * Phase 3: Enhanced edges with conditions
 */
export interface Edge {
  from: string;
  to: string;
  condition: 'always' | 'on-success' | 'on-error' | 'conditional';
}

/**
 * Source location
 */
export interface SourceLocation {
  filePath: string;
  line: number;
}

/**
 * Phase 4: Security finding attached to nodes
 */
export interface SecurityFinding {
  id: string;
  type: FindingType;
  severity: Severity;
  message: string;
  remediation?: string;
  cwe?: string;
}

/**
 * Phase 4: Finding classification
 */
export type FindingType =
  | 'missing-authentication'
  | 'weak-authentication'
  | 'missing-authorization'
  | 'auth-after-handler'
  | 'conditional-auth'
  | 'missing-jwt-verification'
  | 'missing-error-handling'
  | 'missing-next-call'
  | 'missing-rbac'
  | 'privilege-escalation-risk';

/**
 * Phase 4: Severity levels
 */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';