/**
 * IR construction — Enhanced
 * Builds framework-agnostic execution graph with auth semantics.
 * Now supports global middleware prepending to all routes.
 */

import type { ParsedFile, FunctionReference } from '../parser/index.js';
import type { GlobalMiddlewareDefinition } from '../parser/express.js';
import type {
  ExecutionGraph,
  Route,
  ExecutionNode,
  Edge,
  NodeKind,
  AuthType,
  AuthEnforcement,
  GlobalMiddlewareEntry,
  NodeMetadata,
} from './types.js';

/**
 * Classify middleware/handler as auth or regular
 */
function classifyNode(
  ref: FunctionReference,
  fileImports: string[],
  isHandler: boolean
): {
  kind: NodeKind;
  authType?: AuthType;
  enforcement?: AuthEnforcement;
} {
  const name = ref.name.toLowerCase();

  // JWT verification detection
  if (ref.hasJWTVerification) {
    const authType: AuthType =
      ref.jwtVerifyMethod === 'passport' ? 'custom' : 'jwt-verification';
    return {
      kind: 'auth',
      authType,
      enforcement: ref.hasErrorHandling ? 'hard' : 'soft',
    };
  }

  // Session detection
  if (name.includes('session') || fileImports.some(imp => imp.includes('session'))) {
    return {
      kind: 'auth',
      authType: 'session-check',
      enforcement: 'soft',
    };
  }

  // Common auth middleware patterns
  const authPatterns = [
    'auth', 'authenticate', 'verify', 'protect',
    'guard', 'secure', 'requireauth', 'ensureauth',
  ];

  if (authPatterns.some(pattern => name.includes(pattern))) {
    let authType: AuthType = 'custom';
    if (name.includes('jwt') || fileImports.some(imp => imp.includes('jwt'))) {
      authType = 'jwt-verification';
    } else if (name.includes('session')) {
      authType = 'session-check';
    } else if (name.includes('apikey') || name.includes('api-key')) {
      authType = 'api-key';
    } else if (name.includes('basic')) {
      authType = 'basic-auth';
    } else if (name.includes('oauth')) {
      authType = 'oauth';
    }

    let enforcement: AuthEnforcement = 'hard';
    if (ref.conditionalAuth) {
      enforcement = 'conditional';
    } else if (!ref.callsNext && !isHandler) {
      enforcement = 'hard';
    } else if (ref.callsNext && !ref.hasErrorHandling) {
      enforcement = 'soft';
    }

    return { kind: 'auth', authType, enforcement };
  }

  // RBAC middleware detection
  if (
    ref.rolesChecked.length > 0 ||
    name.includes('role') ||
    name.includes('permission') ||
    name.includes('authorize') ||
    name.includes('admin')
  ) {
    return { kind: 'auth', authType: 'custom', enforcement: 'hard' };
  }

  // Regular middleware or handler
  return { kind: isHandler ? 'handler' : 'middleware' };
}

/**
 * Build execution graph with global middleware support.
 * Uses a closure-based counter to avoid global mutable state.
 */
export function buildExecutionGraph(
  parsedFiles: ParsedFile[],
  globalMiddleware: GlobalMiddlewareDefinition[] = []
): ExecutionGraph {
  const routes: Route[] = [];
  const nodes = new Map<string, ExecutionNode>();
  const edges: Edge[] = [];
  let nodeCounter = 0;
  const sessionMiddleware: string[] = [];

  function createNode(
    type: NodeKind,
    name: string,
    metadata: NodeMetadata
  ): string {
    const id = `node_${nodeCounter++}`;
    nodes.set(id, { id, type, name, metadata });
    return id;
  }

  // Pre-classify global middleware definitions
  const globalEntries: GlobalMiddlewareEntry[] = [];
  for (const gm of globalMiddleware) {
    const classification = classifyNode(gm.ref, [], false);
    if (classification.authType === 'session-check') {
      sessionMiddleware.push(gm.ref.name);
    }
    globalEntries.push({
      name: gm.ref.name,
      filePath: gm.filePath,
      line: gm.line,
      isAuth: classification.kind === 'auth',
      authType: classification.authType,
    });
  }

  // Process each file's routes
  for (const file of parsedFiles) {
    for (const routeDef of file.routes) {
      const nodeIds: string[] = [];

      // Prepend global middleware nodes for this route's execution trace
      for (const gm of globalMiddleware) {
        const classification = classifyNode(gm.ref, [], false);
        const nodeId = createNode(classification.kind, gm.ref.name, {
          isAsync: gm.ref.isAsync,
          referencesUser: gm.ref.referencesUser,
          fileImports: [],
          sourceLocation: { filePath: gm.filePath, line: gm.line },
          authType: classification.authType,
          enforcement: classification.enforcement,
          rolesChecked: gm.ref.rolesChecked,
          hasRoleValidation: gm.ref.rolesChecked.length > 0,
          hasJWTVerification: gm.ref.hasJWTVerification,
          jwtVerifyMethod: gm.ref.jwtVerifyMethod,
          callsNext: gm.ref.callsNext,
          hasErrorHandling: gm.ref.hasErrorHandling,
          conditionalAuth: gm.ref.conditionalAuth,
          findings: [],
        });
        nodeIds.push(nodeId);
      }

      // Process route-specific middleware chain
      for (const mw of routeDef.middleware) {
        const classification = classifyNode(mw, routeDef.fileImports, false);

        if (classification.authType === 'session-check') {
          sessionMiddleware.push(mw.name);
        }

        const nodeId = createNode(classification.kind, mw.name, {
          isAsync: mw.isAsync,
          referencesUser: mw.referencesUser,
          fileImports: routeDef.fileImports,
          sourceLocation: {
            filePath: routeDef.filePath,
            line: routeDef.line,
          },
          authType: classification.authType,
          enforcement: classification.enforcement,
          rolesChecked: mw.rolesChecked,
          hasRoleValidation: mw.rolesChecked.length > 0,
          hasJWTVerification: mw.hasJWTVerification,
          jwtVerifyMethod: mw.jwtVerifyMethod,
          callsNext: mw.callsNext,
          hasErrorHandling: mw.hasErrorHandling,
          conditionalAuth: mw.conditionalAuth,
          findings: [],
        });

        nodeIds.push(nodeId);
      }

      // Process handler
      const handlerClass = classifyNode(
        routeDef.handler,
        routeDef.fileImports,
        true
      );

      const handlerNodeId = createNode(handlerClass.kind, routeDef.handler.name, {
        isAsync: routeDef.handler.isAsync,
        referencesUser: routeDef.handler.referencesUser,
        fileImports: routeDef.fileImports,
        sourceLocation: {
          filePath: routeDef.filePath,
          line: routeDef.line,
        },
        authType: handlerClass.authType,
        enforcement: handlerClass.enforcement,
        rolesChecked: routeDef.handler.rolesChecked,
        hasRoleValidation: routeDef.handler.rolesChecked.length > 0,
        hasJWTVerification: routeDef.handler.hasJWTVerification,
        jwtVerifyMethod: routeDef.handler.jwtVerifyMethod,
        callsNext: routeDef.handler.callsNext,
        hasErrorHandling: routeDef.handler.hasErrorHandling,
        conditionalAuth: routeDef.handler.conditionalAuth,
        findings: [],
      });

      nodeIds.push(handlerNodeId);

      // Build execution edges with conditions along this route's isolated chain
      for (let i = 0; i < nodeIds.length - 1; i++) {
        const fromId = nodeIds[i];
        const toId = nodeIds[i + 1];
        if (!fromId || !toId) continue;

        const fromNode = nodes.get(fromId);
        let condition: Edge['condition'] = 'always';

        if (fromNode && fromNode.type === 'auth') {
          if (fromNode.metadata.hasErrorHandling) {
            condition = 'on-success';
          } else if (fromNode.metadata.conditionalAuth) {
            condition = 'conditional';
          }
        }

        edges.push({ from: fromId, to: toId, condition });
      }

      // Create route entry
      const routeId = `route_${routes.length}`;
      const entryNodeId = nodeIds[0];
      if (!entryNodeId) continue;

      routes.push({
        id: routeId,
        method: routeDef.method,
        path: routeDef.path,
        entryNodeId,
        sourceLocation: {
          filePath: routeDef.filePath,
          line: routeDef.line,
        },
      });
    }
  }

  return {
    routes,
    nodes,
    edges,
    sessionMiddleware: Array.from(new Set(sessionMiddleware)),
    globalMiddleware: globalEntries,
  };
}