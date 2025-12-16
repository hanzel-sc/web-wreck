/**
 * IR construction from parsed routes
 * Builds framework-agnostic execution graph (DAG)
 */

import type { ParsedFile } from '../parser/index.js';
import type { ExecutionGraph, Route, ExecutionNode, Edge } from './types.js';

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
        const nodeId = createNode(nodes, 'middleware', mw.name, {
          isAsync: mw.isAsync,
          referencesUser: mw.referencesUser,
          fileImports: routeDef.fileImports,
          isAuthRelated: false,
          sourceLocation: {
            filePath: routeDef.filePath,
            line: routeDef.line,
          },
        });

        nodeIds.push(nodeId);
      }

      // Handler node
      const handlerNodeId = createNode(
        nodes,
        'handler',
        routeDef.handler.name,
        {
          isAsync: routeDef.handler.isAsync,
          referencesUser: routeDef.handler.referencesUser,
          fileImports: routeDef.fileImports,
          isAuthRelated: false,
          sourceLocation: {
            filePath: routeDef.filePath,
            line: routeDef.line,
          },
        }
      );

      nodeIds.push(handlerNodeId);

      // Execution edges
      for (let i = 0; i < nodeIds.length - 1; i++) {
        edges.push({
          from: nodeIds[i],
          to: nodeIds[i + 1],
        });
      }

      // Route entry
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

function createNode(
  nodes: Map<string, ExecutionNode>,
  type: 'middleware' | 'handler',
  name: string,
  metadata: ExecutionNode['metadata']
): string {
  const id = `node_${nodeCounter++}`;
  nodes.set(id, { id, type, name, metadata });
  return id;
}
