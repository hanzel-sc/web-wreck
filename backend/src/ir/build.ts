/**
 * IR construction from parsed routes
 * Builds framework-agnostic execution graph (DAG)
 */

import type { ParsedFile, FunctionReference } from '../parser/index.js';
import type { ExecutionGraph, Route, ExecutionNode, Edge, NodeKind } from './types.js';

let nodeCounter = 0;

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

      // Middleware nodes
      for (const mw of routeDef.middleware) {
        const { kind, authType } = classifyNode(mw, false);

        const nodeId = createNode(nodes, kind, mw.name, {
          isAsync: mw.isAsync,
          referencesUser: mw.referencesUser,
          fileImports: routeDef.fileImports,
          sourceLocation: {
            filePath: routeDef.filePath,
            line: routeDef.line,
          },
          authType,
          enforcement: mw.referencesUser ? 'hard' : 'optional',
        });


        nodeIds.push(nodeId);
      }

      // Handler node
      const handlerClass = classifyNode(routeDef.handler, true);

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
        }
      );


      nodeIds.push(handlerNodeId);

      // Execution edges
      for (let i = 0; i < nodeIds.length - 1; i++) {
        edges.push({
          from: nodeIds[i],
          to: nodeIds[i + 1],
          condition: 'always',
        });
      }

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


function classifyNode(
  ref: FunctionReference,
  isHandler: boolean
): { kind: NodeKind; authType?: 'entry' | 'enforcer' } {

  const name = ref.name.toLowerCase();

  if (isHandler && (name.includes('login') || name.includes('register'))) {
    return { kind: 'auth', authType: 'entry' };
  }

  if (name.includes('auth') || name.includes('verify') || name.includes('jwt')) {
    return { kind: 'auth', authType: 'enforcer' };
  }

  return { kind: isHandler ? 'handler' : 'middleware' };
}


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

