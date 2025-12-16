/**
 * Express route extraction
 * Compiler-style frontend for Express routing
 */

import traverse from '@babel/traverse';
import * as t from '@babel/types';
import type { File } from '@babel/types';
import type { RouteDefinition, FunctionReference } from './index.js';

const traverseFn =
  typeof traverse === 'function'
    ? traverse
    : (traverse as any).default;

const HTTP_METHODS = new Set([
  'get',
  'post',
  'put',
  'delete',
  'patch',
  'use',
  'all',
]);

function extractImports(ast: File): string[] {
  const imports: string[] = [];

  traverseFn(ast, {
    ImportDeclaration(path) {
      imports.push(path.node.source.value);
    },
    CallExpression(path) {
      const { node } = path;
      if (
        t.isIdentifier(node.callee, { name: 'require' }) &&
        node.arguments.length === 1 &&
        t.isStringLiteral(node.arguments[0])
      ) {
        imports.push(node.arguments[0].value);
      }
    },
  });

  return imports;
}

function containsReqUser(fn: t.Function): boolean {
  let found = false;

  t.traverseFast(fn.body, node => {
    if (
      t.isMemberExpression(node) &&
      t.isIdentifier(node.object, { name: 'req' }) &&
      t.isIdentifier(node.property, { name: 'user' })
    ) {
      found = true;
    }
  });

  return found;
}


function extractFunctionReference(node: t.Node): FunctionReference {
  if (t.isArrowFunctionExpression(node) || t.isFunctionExpression(node)) {
    return {
      name: '<inline>',
      type: 'inline',
      isAsync: !!node.async,
      referencesUser: containsReqUser(node),
    };
  }

  if (t.isIdentifier(node)) {
    return {
      name: node.name,
      type: 'identifier',
      isAsync: false,
      referencesUser: false,
    };
  }

  return {
    name: '<unknown>',
    type: 'unknown',
    isAsync: false,
    referencesUser: false,
  };
}



export function extractExpressRoutes(
  ast: File,
  filePath: string
): RouteDefinition[] {
  const routes: RouteDefinition[] = [];
  const fileImports = extractImports(ast);

  traverseFn(ast, {
    CallExpression(path) {
      const { node } = path;

      if (!t.isMemberExpression(node.callee)) return;
      if (!t.isIdentifier(node.callee.property)) return;

      const method = node.callee.property.name;
      if (!HTTP_METHODS.has(method)) return;

      if (!t.isIdentifier(node.callee.object)) return;

      // Only string literal paths for v0
      const firstArg = node.arguments[0];
      if (!t.isStringLiteral(firstArg)) return;

      const handlers = node.arguments.slice(1);
      if (handlers.length === 0) return;

      const middleware: FunctionReference[] = [];
      let handler: FunctionReference | null = null;

      handlers.forEach((arg, index) => {
        const ref = extractFunctionReference(arg);
        if (index === handlers.length - 1) {
          handler = ref;
        } else {
          middleware.push(ref);
        }
      });

      if (!handler) return;

      routes.push({
        method: method.toUpperCase(),
        path: firstArg.value,
        filePath,
        line: node.loc?.start.line ?? 0,
        middleware,
        handler,
        fileImports,
      });
    },
  });

  return routes;
}
