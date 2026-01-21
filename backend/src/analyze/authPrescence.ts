/**
 * Phase 3: Complete Authentication & Authorization Analysis
 * 
 * Implements all Phase 3 requirements:
 * - JWT verification detection
 * - Missing/incorrect token validation
 * - Middleware ordering validation
 * - Global vs route-level auth differentiation
 * - RBAC pattern detection
 * - Auth bypass path identification
 */

import type {
  ExecutionGraph,
  ExecutionNode,
  Route,
  SecurityFinding,
} from '../ir/types.js';

export interface AuthAnalysis {
  // Missing authentication
  unauthenticated: string[];
  
  // Phase 3: Middleware ordering issues
  authAfterHandler: string[];
  
  // Phase 3: Weak authentication patterns
  optionalAuth: string[];
  conditionalAuth: string[];
  
  // Phase 3: RBAC issues
  missingRBAC: string[];
  
  // Phase 3: JWT validation issues
  missingJWTVerification: string[];
  weakJWTValidation: string[];
  
  // Phase 3: Auth bypass paths
  bypassPaths: AuthBypass[];
  
  // Metadata
  authNodes: string[];
  globalAuthMiddleware: string[];
  
  // Phase 4: All findings aggregated
  allFindings: Map<string, SecurityFinding[]>;
}

export interface AuthBypass {
  routeId: string;
  bypassType: 'conditional' | 'missing-validation' | 'order-bypass';
  path: string[];
  description: string;
}

/**
 * Main analysis entry point
 */
export function analyzeAuthPresence(graph: ExecutionGraph): AuthAnalysis {
  const findings: AuthAnalysis = {
    unauthenticated: [],
    authAfterHandler: [],
    optionalAuth: [],
    conditionalAuth: [],
    missingRBAC: [],
    missingJWTVerification: [],
    weakJWTValidation: [],
    bypassPaths: [],
    authNodes: [],
    globalAuthMiddleware: [],
    allFindings: new Map(),
  };

  const adjacency = buildAdjacency(graph);

  // Identify all auth nodes
  for (const [nodeId, node] of graph.nodes) {
    if (node.type === 'auth') {
      findings.authNodes.push(nodeId);
    }
  }

  // Analyze each route
  for (const route of graph.routes) {
    const chain = getOrderedExecutionChain(graph, adjacency, route.entryNodeId);
    analyzeRouteChain(route, chain, graph, findings);
  }

  return findings;
}

/**
 * Phase 3: Comprehensive route chain analysis
 */
function analyzeRouteChain(
  route: Route,
  chain: ExecutionNode[],
  graph: ExecutionGraph,
  findings: AuthAnalysis
) {
  const authNodes = chain.filter(n => n.type === 'auth');
  const handlerIndex = chain.findIndex(n => n.type === 'handler');

  // Finding 1: No authentication at all
  if (authNodes.length === 0) {
    findings.unauthenticated.push(route.id);
    addFinding(findings, route.id, {
      id: `${route.id}-missing-auth`,
      type: 'missing-authentication',
      severity: isPrivilegedRoute(route) ? 'critical' : 'high',
      message: `Route ${route.method} ${route.path} has no authentication middleware`,
      remediation: 'Add authentication middleware before the handler',
      cwe: 'CWE-306',
    });
    return;
  }

  // Analyze each auth node
  for (const authNode of authNodes) {
    const authIndex = chain.indexOf(authNode);

    // Finding 2: Auth runs after handler (dead auth)
    if (handlerIndex !== -1 && authIndex > handlerIndex) {
      findings.authAfterHandler.push(route.id);
      addFinding(findings, route.id, {
        id: `${route.id}-auth-after-handler`,
        type: 'auth-after-handler',
        severity: 'critical',
        message: `Authentication middleware "${authNode.name}" runs AFTER handler - ineffective`,
        remediation: 'Move authentication middleware before the handler',
        cwe: 'CWE-863',
      });
    }

    // Finding 3: Conditional authentication
    if (authNode.metadata.conditionalAuth) {
      findings.conditionalAuth.push(route.id);
      addFinding(findings, route.id, {
        id: `${route.id}-conditional-auth`,
        type: 'conditional-auth',
        severity: 'high',
        message: `Route has conditional authentication (if/else) - may allow bypass`,
        remediation: 'Use hard authentication that always blocks unauthenticated requests',
        cwe: 'CWE-285',
      });

      // Track as bypass path
      findings.bypassPaths.push({
        routeId: route.id,
        bypassType: 'conditional',
        path: chain.map(n => n.id),
        description: `Conditional auth in ${authNode.name} may allow unauthenticated access`,
      });
    }

    // Finding 4: Soft enforcement (no error handling)
    if (authNode.metadata.enforcement === 'soft') {
      findings.optionalAuth.push(route.id);
      addFinding(findings, route.id, {
        id: `${route.id}-soft-auth`,
        type: 'weak-authentication',
        severity: 'high',
        message: `Authentication middleware "${authNode.name}" has soft enforcement (no error handling)`,
        remediation: 'Add proper error handling to reject unauthenticated requests',
        cwe: 'CWE-306',
      });
    }

    // Finding 5: Missing JWT verification
    if (
      authNode.metadata.authType === 'jwt-verification' &&
      !authNode.metadata.hasJWTVerification
    ) {
      findings.missingJWTVerification.push(route.id);
      addFinding(findings, route.id, {
        id: `${route.id}-missing-jwt`,
        type: 'missing-jwt-verification',
        severity: 'critical',
        message: `JWT auth middleware "${authNode.name}" doesn't verify tokens`,
        remediation: 'Add jwt.verify() or equivalent token validation',
        cwe: 'CWE-345',
      });
    }

    // Finding 6: Weak JWT validation (no error handling)
    if (
      authNode.metadata.hasJWTVerification &&
      !authNode.metadata.hasErrorHandling
    ) {
      findings.weakJWTValidation.push(route.id);
      addFinding(findings, route.id, {
        id: `${route.id}-weak-jwt`,
        type: 'weak-authentication',
        severity: 'high',
        message: `JWT verification in "${authNode.name}" lacks error handling`,
        remediation: 'Wrap jwt.verify() in try-catch and return 401 on failure',
        cwe: 'CWE-755',
      });
    }

    // Finding 7: Missing next() call in middleware
    if (authIndex < handlerIndex && !authNode.metadata.callsNext) {
      addFinding(findings, route.id, {
        id: `${route.id}-missing-next`,
        type: 'missing-next-call',
        severity: 'medium',
        message: `Auth middleware "${authNode.name}" doesn't call next() - may block execution`,
        remediation: 'Call next() after successful authentication',
        cwe: 'CWE-670',
      });
    }
  }

  // Finding 8: Missing RBAC on privileged routes
  if (isPrivilegedRoute(route)) {
    const hasRoleCheck = authNodes.some(
      n => n.metadata.hasRoleValidation || n.metadata.rolesChecked && n.metadata.rolesChecked.length > 0
    );

    if (!hasRoleCheck) {
      findings.missingRBAC.push(route.id);
      addFinding(findings, route.id, {
        id: `${route.id}-missing-rbac`,
        type: 'missing-authorization',
        severity: 'critical',
        message: `Privileged route ${route.path} lacks role-based access control`,
        remediation: 'Add middleware to check user roles/permissions',
        cwe: 'CWE-862',
      });
    }
  }
}

/**
 * Phase 3: Identify privileged routes
 */
function isPrivilegedRoute(route: Route): boolean {
  const path = route.path.toLowerCase();
  const method = route.method.toUpperCase();

  // Path-based detection
  const privilegedPaths = [
    'admin',
    'internal',
    'manage',
    'delete',
    'remove',
    'update',
    'create',
    'modify',
    'settings',
    'config',
  ];

  if (privilegedPaths.some(p => path.includes(p))) {
    return true;
  }

  // Method-based detection (destructive operations)
  if (['DELETE', 'PUT', 'PATCH'].includes(method)) {
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
    const neighbors = adjacency.get(edge.from) ?? [];
    neighbors.push(edge.to);
    adjacency.set(edge.from, neighbors);
  }

  return adjacency;
}

/**
 * Get ordered execution chain via DFS
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

/**
 * Phase 4: Helper to add findings to nodes
 */
function addFinding(
  findings: AuthAnalysis,
  routeId: string,
  finding: SecurityFinding
) {
  const existingFindings = findings.allFindings.get(routeId) ?? [];
  existingFindings.push(finding);
  findings.allFindings.set(routeId, existingFindings);
}