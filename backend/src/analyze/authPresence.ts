/**
 * Comprehensive Authentication & Authorization Analysis
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
} from '../ir/types.js';
import { buildAdjacency, getOrderedExecutionChain } from '../util/graph.js';

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

    // Identify all auth nodes (including global middleware auth nodes)
    for (const [nodeId, node] of graph.nodes) {
        if (node.type === 'auth') {
            findings.authNodes.push(nodeId);
        }
    }

    // Track global auth middleware
    if (graph.globalMiddleware) {
        for (const gm of graph.globalMiddleware) {
            if (gm.isAuth) {
                findings.globalAuthMiddleware.push(gm.name);
            }
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
 * Route chain analysis with reporting
 */
function analyzeRouteChain(
    route: Route,
    chain: ExecutionNode[],
    _graph: ExecutionGraph,
    findings: AuthAnalysis
): void {
    const authNodes = chain.filter(n => n.type === 'auth');
    const handlerIndex = chain.findIndex(n => n.type === 'handler');
    const routeId = route.id;
    const firstNode = chain[0];

    // Finding 1: No authentication at all
    if (authNodes.length === 0) {
        const isPublic = isPublicRoute(route);
        const isAuthFlow = isAuthenticationRoute(route);
        const isRouterMount = isRouterMountRoute(route);

        if (isAuthFlow) {
            addFinding(findings, routeId, {
                id: `${routeId}-auth-flow`,
                type: 'public-endpoint',
                category: 'authentication',
                severity: 'info',
                riskScore: 0,
                message: `Route ${route.method} ${route.path} is an authentication flow endpoint`,
                remediation: 'No action needed - authentication endpoints should be publicly accessible.',
                affectedNodeIds: firstNode ? [firstNode.id] : [],
            });
            return;
        }

        if (isRouterMount) {
            addFinding(findings, routeId, {
                id: `${routeId}-router-mount`,
                type: 'public-endpoint',
                category: 'authentication',
                severity: 'info',
                riskScore: 0,
                message: `Route ${route.method} ${route.path} is a router mount point`,
                remediation: 'Router mounts delegate auth to sub-routes. Review the mounted router separately.',
                affectedNodeIds: firstNode ? [firstNode.id] : [],
            });
            return;
        }

        if (isPublic) {
            addFinding(findings, routeId, {
                id: `${routeId}-public-route`,
                type: 'public-endpoint',
                category: 'authentication',
                severity: 'info',
                riskScore: 0,
                message: `Route ${route.method} ${route.path} is a public endpoint (no authentication required)`,
                remediation: 'No action needed if this endpoint is intended to be public.',
                affectedNodeIds: firstNode ? [firstNode.id] : [],
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
            affectedNodeIds: firstNode ? [firstNode.id] : [],
        });
        return;
    }

    // Analyze each auth node
    for (const authNode of authNodes) {
        const authIndex = chain.indexOf(authNode);

        // Finding 2: Auth runs after handler
        if (handlerIndex !== -1 && authIndex > handlerIndex) {
            const handlerNode = chain[handlerIndex];
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
                affectedNodeIds: handlerNode
                    ? [authNode.id, handlerNode.id]
                    : [authNode.id],
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
                routeId,
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

        // Finding 5: Session fixation check
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

    // Finding 6: Missing RBAC on privileged routes
    if (isPrivilegedRoute(route)) {
        const hasRoleCheck = authNodes.some(
            n => n.metadata.hasRoleValidation || (n.metadata.rolesChecked && n.metadata.rolesChecked.length > 0)
        );

        if (!hasRoleCheck) {
            const handlerNode = handlerIndex !== -1 ? chain[handlerIndex] : undefined;
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
                affectedNodeIds: handlerNode ? [handlerNode.id] : [],
            });
        }
    }
}

/**
 * Identify public routes (whitelist)
 */
function isPublicRoute(route: Route): boolean {
    const path = route.path.toLowerCase();
    const method = route.method.toUpperCase();

    const publicPaths = [
        'login', 'register', 'signup', 'logout', 'signout',
        'forgot', 'reset', 'verify', 'confirm', 'activate',
        'oauth', 'callback', 'token', 'refresh',
        'public', 'static', 'assets', 'uploads',
        'favicon', 'robots', 'sitemap', 'manifest',
        'health', 'status', 'ping', 'ready', 'live', 'version',
        'docs', 'swagger', 'api-docs', 'openapi', 'graphql',
        '.css', '.js', '.png', '.jpg', '.svg', '.ico', '.woff'
    ];

    if (publicPaths.some(p => path.includes(p))) return true;
    if (path === '/' && method === 'GET') return true;

    return false;
}

/**
 * Identify authentication flow routes
 */
function isAuthenticationRoute(route: Route): boolean {
    const path = route.path.toLowerCase();
    const method = route.method.toUpperCase();
    const filePath = route.sourceLocation.filePath.toLowerCase();

    const authFilePatterns = ['auth.js', 'auth.ts', 'authentication', 'login', 'session'];
    const isAuthFile = authFilePatterns.some(p => filePath.includes(p));

    const authEndpoints = [
        { method: 'POST', patterns: ['login', 'signin', 'register', 'signup', 'logout', 'signout', 'token', 'refresh'] },
        { method: 'GET', patterns: ['logout', 'signout', 'oauth', 'callback', 'verify', 'confirm'] },
    ];

    for (const endpoint of authEndpoints) {
        if (method === endpoint.method) {
            if (endpoint.patterns.some(p => path.includes(p))) {
                return true;
            }
        }
    }

    if (isAuthFile && ['POST', 'GET'].includes(method)) {
        const authPatterns = ['login', 'register', 'logout', 'signup', 'token', 'session', 'password'];
        if (authPatterns.some(p => path.includes(p))) {
            return true;
        }
    }

    return false;
}

/**
 * Identify router mount routes
 */
function isRouterMountRoute(route: Route): boolean {
    const method = route.method.toUpperCase();
    const path = route.path.toLowerCase();

    if (method === 'USE') {
        const routerMountPatterns = [
            '/api/', '/v1/', '/v2/', '/auth', '/users', '/admin',
            '/company', '/student', '/faculty', '/jobs', '/applications'
        ];
        return routerMountPatterns.some(p => path.includes(p)) || path.startsWith('/api');
    }

    return false;
}

/**
 * Identify privileged routes
 */
function isPrivilegedRoute(route: Route): boolean {
    const path = route.path.toLowerCase();
    const method = route.method.toUpperCase();
    const filePath = route.sourceLocation.filePath.toLowerCase();

    if (isPublicRoute(route)) return false;
    if (isAuthenticationRoute(route)) return false;
    if (isRouterMountRoute(route)) return false;

    const authFilePatterns = ['auth.js', 'auth.ts', 'authentication', 'login', 'session'];
    if (authFilePatterns.some(p => filePath.includes(p))) return false;

    const privilegedPaths = [
        'admin', 'internal', 'manage', 'superuser', 'sudo',
        'settings', 'config', 'system', 'audit'
    ];

    if (privilegedPaths.some(p => path.includes(p))) return true;

    if (method === 'DELETE') {
        if (path.includes(':id') || /\/[a-z]+\/\d+/.test(path)) {
            return true;
        }
    }

    return false;
}

/**
 * Helper to add findings
 */
function addFinding(
    findings: AuthAnalysis,
    routeId: string,
    finding: SecurityFinding
): void {
    const existing = findings.allFindings.get(routeId) ?? [];
    existing.push(finding);
    findings.allFindings.set(routeId, existing);
}
