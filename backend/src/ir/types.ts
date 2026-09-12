/**
 * Intermediate Representation (IR) — Enhanced
 * Framework-agnostic execution graph with auth semantics
 */

/**
 * Main IR structure
 */
export interface ExecutionGraph {
  routes: Route[];
  nodes: Map<string, ExecutionNode>;
  edges: Edge[];
  executiveSummary?: ExecutiveSummary;
  sessionMiddleware?: string[];
  globalMiddleware?: GlobalMiddlewareEntry[];
}

/**
 * Global middleware applied to all routes (app.use(fn) without a path)
 */
export interface GlobalMiddlewareEntry {
  name: string;
  filePath: string;
  line: number;
  isAuth: boolean;
  authType?: AuthType;
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
 * Node classification
 */
export type NodeKind = 'middleware' | 'handler' | 'auth';

/**
 * Authentication enforcement modes
 */
export type AuthEnforcement = 'hard' | 'soft' | 'conditional' | 'none';

/**
 * Auth middleware classification
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
 * Enhanced node metadata
 */
export interface NodeMetadata {
  // Basic info
  isAsync: boolean;
  referencesUser: boolean;
  fileImports: string[];
  sourceLocation: SourceLocation;

  // Auth classification
  authType?: AuthType;
  enforcement?: AuthEnforcement;

  // RBAC
  rolesChecked?: string[];
  hasRoleValidation: boolean;

  // JWT specifics
  hasJWTVerification: boolean;
  jwtVerifyMethod?: string | null;

  // Middleware behavior
  callsNext: boolean;
  hasErrorHandling: boolean;
  conditionalAuth: boolean;

  // Security findings
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
 * Enhanced edges with conditions
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
 * Risk scoring
 */
export type RiskScore = number; // 0-100 score

export type FindingCategory =
  | 'authentication'
  | 'authorization'
  | 'cryptography'
  | 'data-protection'
  | 'configuration'
  | 'other';

/**
 * Code context for findings
 */
export interface CodeContext {
  snippet: string;
  startLine: number;
  endLine: number;
}

/**
 * Security finding attached to nodes
 */
export interface SecurityFinding {
  id: string;
  type: FindingType;
  category: FindingCategory;
  severity: Severity;
  message: string;
  remediation?: string;
  cwe?: string;
  riskScore: RiskScore;
  codeContext?: CodeContext;
  affectedNodeIds?: string[];
}

/**
 * Executive summary metrics
 */
export interface ExecutiveSummary {
  riskScore: number;
  criticalIssues: number;
  highIssues: number;
  totalFindings: number;
  remediationComplexity: 'low' | 'medium' | 'high';
}

/**
 * Finding classification
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
  | 'session-fixation-risk'
  | 'broken-access-control'
  | 'privilege-escalation-risk'
  | 'public-endpoint';

/**
 * Severity levels
 */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';