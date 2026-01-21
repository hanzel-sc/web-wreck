/**
 * IR construction - Phase 3 Enhanced
 * Builds framework-agnostic execution graph with auth semantics
 */

import type { ParsedFile, FunctionReference } from '../parser/index.js';
import type {
  ExecutionGraph,
  Route,
  ExecutionNode,
  Edge,
  NodeKind,
  AuthType,
  AuthEnforcement,
} from './types.js';

let nodeCounter = 0;

/**
 * Phase 3: Classify middleware/handler as auth or regular
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

  // Phase 3: JWT verification detection
  if (ref.hasJWTVerification) {
    return {
      kind: 'auth',
      authType: 'jwt-verification',
      enforcement: ref.hasErrorHandling ? 'hard' : 'soft',
    };
  }

  // Phase 3: Common auth middleware patterns
  const authPatterns = [
    'auth',
    'authenticate',
    'verify',
    'protect',
    'guard',
    'secure',
    'requireauth',
    'ensureauth',
  ];

  if (authPatterns.some(pattern => name.includes(pattern))) {
    // Determine auth type from name and imports
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

    // Determine enforcement level
    let enforcement: AuthEnforcement = 'hard';
    
    if (ref.conditionalAuth) {
      enforcement = 'conditional';
    } else if (!ref.callsNext && !isHandler) {
      // Middleware that doesn't call next() is likely blocking
      enforcement = 'hard';
    } else if (ref.callsNext && !ref.hasErrorHandling) {
      // Calls next() without error handling might be soft
      enforcement = 'soft';
    }

    return { kind: 'auth', authType, enforcement };
  }

  // Phase 3: RBAC middleware detection
  if (
    ref.rolesChecked.length > 0 ||
    name.includes('role') ||
    name.includes('permission') ||
    name.includes('authorize')
  ) {
    return {
      kind: 'auth',
      authType: 'custom',
      enforcement: 'hard',
    };
  }

  // Regular middleware or handler
  return {
    kind: isHandler ? 'handler' : 'middleware',
  };
}

/**
 * Phase 3: Build execution graph with enhanced semantics
 */
export function buildExecutionGraph(
  parsedFiles: ParsedFile[]
): ExecutionGraph {
  const routes: Route[] = [];
  const nodes = new Map<string, ExecutionNode>();
  const edges: Edge[] = [];

  nodeCounter = 0;

  for (const file of parsedFiles) {
    for (const routeDef of file.routes) {
      const nodeIds: string[] = [];

      // Process middleware chain
      for (const mw of routeDef.middleware) {
        const classification = classifyNode(mw, routeDef.fileImports, false);

        const nodeId = createNode(nodes, classification.kind, mw.name, {
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
          findings: [], // Phase 4: Will be populated by analysis
        });

        nodeIds.push(nodeId);
      }

      // Process handler
      const handlerClass = classifyNode(
        routeDef.handler,
        routeDef.fileImports,
        true
      );

      const handlerNodeId = createNode(
        nodes,
        handlerClass.kind,
        routeDef.handler.name,
        {
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
        }
      );

      nodeIds.push(handlerNodeId);

      // Build execution edges with conditions
      for (let i = 0; i < nodeIds.length - 1; i++) {
        const fromNode = nodes.get(nodeIds[i]);
        
        // Determine edge condition based on middleware behavior
        let condition: Edge['condition'] = 'always';
        
        if (fromNode && fromNode.type === 'auth') {
          if (fromNode.metadata.hasErrorHandling) {
            condition = 'on-success';
          } else if (fromNode.metadata.conditionalAuth) {
            condition = 'conditional';
          }
        }

        edges.push({
          from: nodeIds[i],
          to: nodeIds[i + 1],
          condition,
        });
      }

      // Create route entry
      const routeId = `route_${routes.length}`;
      routes.push({
        id: routeId,
        method: routeDef.method,
        path: routeDef.path,
        entryNodeId: nodeIds[0],
        sourceLocation: {
          filePath: routeDef.filePath,
          line: routeDef.line,
        },
      });
    }
  }

  return { routes, nodes, edges };
}

/**
 * Helper to create and register a node
 */
function createNode(
  nodes: Map<string, ExecutionNode>,
  type: NodeKind,
  name: string,
  metadata: ExecutionNode['metadata']
): string {
  const id = `node_${nodeCounter++}`;
  nodes.set(id, { id, type, name, metadata });
  return id;
}