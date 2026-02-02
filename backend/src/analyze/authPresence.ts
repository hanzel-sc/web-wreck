/**
 * Phase 3 & 4: Comprehensive Authentication & Authorization Analysis
 * 
 * Implements:
 * - JWT/Passport/Session detection
 * - Risk scoring per finding
 * - Categorization for reporting
 * - Bypass path identification
 */

import type {
    ExecutionGraph,
    ExecutionNode,
    Route,
    SecurityFinding,
    RiskScore,
    FindingCategory,
} from '../ir/types.js';

export interface AuthAnalysis {
    unauthenticated: string[];
    authAfterHandler: string[];
    optionalAuth: string[];
    conditionalAuth: string[];
    missingRBAC: string[];
    missingJWTVerification: string[];
    weakJWTValidation: string[];
    bypassPaths: AuthBypass[];
    authNodes: string[];
    globalAuthMiddleware: string[];
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
 * Route chain analysis with Phase 4 reporting
 */
function analyzeRouteChain(
    route: Route,
    chain: ExecutionNode[],
    graph: ExecutionGraph,
    findings: AuthAnalysis
) {
    const authNodes = chain.filter(n => n.type === 'auth');
    const handlerIndex = chain.findIndex(n => n.type === 'handler');
    const routeId = route.id;

    // Finding 1: No authentication at all
    if (authNodes.length === 0) {
        const isPublic = isPublicRoute(route);
        if (isPublic) {
            // Log as informational if it's a known public route
            addFinding(findings, routeId, {
                id: `${routeId}-public-route`,
                type: 'public-endpoint',
                category: 'authentication',
                severity: 'info',
                riskScore: 0,
                message: `Route ${route.method} ${route.path} is a public endpoint (no authentication required)`,
                remediation: 'No action needed if this endpoint is intended to be public.',
                affectedNodeIds: [chain[0]?.id],
            });
            return;
        }

        findings.unauthenticated.push(routeId);
        const privileged = isPrivilegedRoute(route);
        addFinding(findings, routeId, {
            id: `${routeId}-missing-auth`,
            type: 'missing-authentication',
            category: 'authentication',
            severity: privileged ? 'critical' : 'medium',
            riskScore: privileged ? 90 : 40,
            message: `Route ${route.method} ${route.path} has no authentication middleware`,
            remediation: 'Add authentication middleware (e.g., passport.authenticate() or JWT verify) before the handler',
            cwe: 'CWE-306',
            affectedNodeIds: [chain[0]?.id],
        });
        return;
    }

    // Analyze each auth node
    for (const authNode of authNodes) {
        const authIndex = chain.indexOf(authNode);

        // Finding 2: Auth runs after handler
        if (handlerIndex !== -1 && authIndex > handlerIndex) {
            findings.authAfterHandler.push(routeId);
            addFinding(findings, routeId, {
                id: `${routeId}-auth-after-handler`,
                type: 'auth-after-handler',
                category: 'authorization',
                severity: 'critical',
                riskScore: 95,
                message: `Authentication middleware "${authNode.name}" runs AFTER handler - it will never be executed for this route`,
                remediation: 'Move authentication middleware to the beginning of the middleware chain',
                cwe: 'CWE-863',
                affectedNodeIds: [authNode.id, chain[handlerIndex].id],
            });
        }

        // Finding 3: Conditional authentication
        if (authNode.metadata.conditionalAuth) {
            findings.conditionalAuth.push(routeId);
            addFinding(findings, routeId, {
                id: `${routeId}-conditional-auth`,
                type: 'conditional-auth',
                category: 'authentication',
                severity: 'high',
                riskScore: 75,
                message: `Route has conditional authentication in "${authNode.name}" (if/else) - which may allow unauthenticated bypass`,
                remediation: 'Ensure authentication is enforced strictly for all execution paths',
                cwe: 'CWE-285',
                affectedNodeIds: [authNode.id],
            });

            findings.bypassPaths.push({
                routeId: routeId,
                bypassType: 'conditional',
                path: chain.map(n => n.id),
                description: `Conditional auth in ${authNode.name} may allow unauthenticated access`,
            });
        }

        // Finding 4: Soft enforcement
        if (authNode.metadata.enforcement === 'soft') {
            findings.optionalAuth.push(routeId);
            addFinding(findings, routeId, {
                id: `${routeId}-soft-auth`,
                type: 'weak-authentication',
                category: 'authentication',
                severity: 'high',
                riskScore: 65,
                message: `Authentication middleware "${authNode.name}" has soft enforcement (no error handling if auth fails)`,
                remediation: 'Add proper error handling (e.g., res.status(401).send()) to reject unauthenticated requests',
                cwe: 'CWE-306',
                affectedNodeIds: [authNode.id],
            });
        }

        // Finding 5: Special session fixation check
        if (authNode.metadata.authType === 'session-check' && !authNode.metadata.hasErrorHandling) {
            addFinding(findings, routeId, {
                id: `${routeId}-session-fixation`,
                type: 'session-fixation-risk',
                category: 'authentication',
                severity: 'medium',
                riskScore: 50,
                message: `Session check in "${authNode.name}" may be vulnerable to session fixation if session is not regenerated after login`,
                remediation: 'Use req.session.regenerate() after successful login to prevent session fixation',
                cwe: 'CWE-384',
                affectedNodeIds: [authNode.id],
            });
        }
    }

    // Finding 8: Missing RBAC on privileged routes
    if (isPrivilegedRoute(route)) {
        const hasRoleCheck = authNodes.some(
            n => n.metadata.hasRoleValidation || (n.metadata.rolesChecked && n.metadata.rolesChecked.length > 0)
        );

        if (!hasRoleCheck) {
            findings.missingRBAC.push(routeId);
            addFinding(findings, routeId, {
                id: `${routeId}-missing-rbac`,
                type: 'missing-authorization',
                category: 'authorization',
                severity: 'critical',
                riskScore: 85,
                message: `Privileged route ${route.method} ${route.path} lacks role-based access control (RBAC)`,
                remediation: 'Add authorization middleware to check user roles/permissions before allowing access',
                cwe: 'CWE-862',
                affectedNodeIds: [chain[handlerIndex]?.id],
            });
        }
    }
}

/**
 * Identify public routes (whitelist)
 */
function isPublicRoute(route: Route): boolean {
    const path = route.path.toLowerCase();

    const publicPaths = [
        'login', 'register', 'signup', 'public', 'static', 'assets',
        'favicon', 'health', 'status', 'ping', 'docs', 'swagger'
    ];

    return publicPaths.some(p => path.includes(p));
}

/**
 * Identify privileged routes
 */
function isPrivilegedRoute(route: Route): boolean {
    const path = route.path.toLowerCase();
    const method = route.method.toUpperCase();

    // Whitelist public routes first
    if (isPublicRoute(route)) return false;

    const privilegedPaths = [
        'admin', 'internal', 'manage', 'delete', 'remove', 'update',
        'create', 'modify', 'settings', 'config', 'user/pw', 'profile/edit'
    ];

    if (privilegedPaths.some(p => path.includes(p))) return true;
    if (['DELETE', 'PUT', 'PATCH'].includes(method)) return true;

    return false;
}

/**
 * Build adjacency list
 */
function buildAdjacency(graph: ExecutionGraph): Map<string, string[]> {
    const adjacency = new Map<string, string[]>();
    for (const [nodeId] of graph.nodes) adjacency.set(nodeId, []);
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
        if (node) result.push(node);
        const neighbors = adjacency.get(nodeId) ?? [];
        for (const next of neighbors) dfs(next);
    }

    dfs(startNodeId);
    return result;
}

/**
 * Helper to add findings
 */
function addFinding(
    findings: AuthAnalysis,
    routeId: string,
    finding: SecurityFinding
) {
    const existing = findings.allFindings.get(routeId) ?? [];
    existing.push(finding);
    findings.allFindings.set(routeId, existing);
}
