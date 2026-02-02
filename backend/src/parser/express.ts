/**
 * Express route extraction - Enhanced for Phase 3
 * Compiler-style frontend for Express routing with deep semantic analysis
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

// Phase 3: JWT library detection patterns
const JWT_LIBRARIES = new Set([
  'jsonwebtoken',
  'express-jwt',
  'jwt-simple',
  '@auth0/express-jwt',
  'passport-jwt',
]);

const PASSPORT_LIBRARIES = new Set([
  'passport',
  'passport-local',
  'passport-http',
  'passport-strategy',
]);

const SESSION_LIBRARIES = new Set([
  'express-session',
  'cookie-session',
  'connect-mongodb-session',
]);

// Phase 3: Common JWT validation patterns
const JWT_VERIFY_PATTERNS = [
  'verify',
  'decode',
  'validateToken',
  'verifyToken',
  'checkToken',
];

/**
 * Extract all imports and requires from a file
 */
function extractImports(ast: File): string[] {
  const imports: string[] = [];

  traverseFn(ast, {
    ImportDeclaration(path: any) {
      imports.push(path.node.source.value);
    },
    CallExpression(path: any) {
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

/**
 * Phase 3: Detect if function references req.user
 */
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

/**
 * Phase 3: Detect next() calls - critical for middleware ordering
 */
function detectNextCall(fn: t.Function): boolean {
  let hasNext = false;

  t.traverseFast(fn.body, node => {
    if (
      t.isCallExpression(node) &&
      t.isIdentifier(node.callee, { name: 'next' })
    ) {
      hasNext = true;
    }
  });

  return hasNext;
}

/**
 * Phase 3: Detect conditional authentication (if (req.user) pattern)
 */
function detectConditionalAuth(fn: t.Function): boolean {
  let found = false;

  t.traverseFast(fn.body, node => {
    if (t.isIfStatement(node)) {
      const test = node.test;

      // Pattern: if (req.user)
      if (
        t.isMemberExpression(test) &&
        t.isIdentifier(test.object, { name: 'req' }) &&
        t.isIdentifier(test.property, { name: 'user' })
      ) {
        found = true;
      }

      // Pattern: if (!req.user)
      if (
        t.isUnaryExpression(test, { operator: '!' }) &&
        t.isMemberExpression(test.argument) &&
        t.isIdentifier(test.argument.object, { name: 'req' }) &&
        t.isIdentifier(test.argument.property, { name: 'user' })
      ) {
        found = true;
      }
    }
  });

  return found;
}

/**
 * Phase 3: Extract role checks from middleware
 * Detects patterns like:
 * - req.user.role
 * - req.user.roles.includes()
 * - Array.from(req.user.permissions)
 */
function extractRoles(fn: t.Function): string[] {
  const roles: Set<string> = new Set();

  t.traverseFast(fn.body, node => {
    // Pattern: req.user.role === 'admin'
    if (
      t.isMemberExpression(node) &&
      t.isMemberExpression(node.object) &&
      t.isIdentifier(node.object.object, { name: 'req' }) &&
      t.isIdentifier(node.object.property, { name: 'user' }) &&
      t.isIdentifier(node.property)
    ) {
      const roleProp = node.property.name;
      if (
        roleProp === 'role' ||
        roleProp === 'roles' ||
        roleProp === 'permissions' ||
        roleProp === 'authorities'
      ) {
        roles.add(roleProp);
      }
    }

    // Pattern: roles.includes('admin')
    if (
      t.isCallExpression(node) &&
      t.isMemberExpression(node.callee) &&
      t.isIdentifier(node.callee.property, { name: 'includes' }) &&
      node.arguments.length > 0 &&
      t.isStringLiteral(node.arguments[0])
    ) {
      roles.add(node.arguments[0].value);
    }
  });

  return Array.from(roles);
}

/**
 * Phase 3: Detect Passport.js authentication
 */
function detectPassportAuth(fn: t.Function, fileImports: string[]): boolean {
  let hasPassport = false;

  const hasPassportImport = fileImports.some(imp =>
    PASSPORT_LIBRARIES.has(imp) || imp.includes('passport')
  );

  if (!hasPassportImport) return false;

  t.traverseFast(fn.body, node => {
    if (t.isCallExpression(node)) {
      // Pattern: passport.authenticate('local')
      if (
        t.isMemberExpression(node.callee) &&
        t.isIdentifier(node.callee.object, { name: 'passport' }) &&
        t.isIdentifier(node.callee.property, { name: 'authenticate' })
      ) {
        hasPassport = true;
      }

      // Pattern: req.isAuthenticated()
      if (
        t.isMemberExpression(node.callee) &&
        t.isIdentifier(node.callee.object, { name: 'req' }) &&
        t.isIdentifier(node.callee.property, { name: 'isAuthenticated' })
      ) {
        hasPassport = true;
      }
    }
  });

  return hasPassport;
}

/**
 * Phase 3: Detect session usage
 */
function detectSessionUsage(fn: t.Function, fileImports: string[]): boolean {
  let hasSession = false;

  const hasSessionImport = fileImports.some(imp =>
    SESSION_LIBRARIES.has(imp) || imp.includes('session')
  );

  t.traverseFast(fn.body, node => {
    if (
      t.isMemberExpression(node) &&
      t.isIdentifier(node.object, { name: 'req' }) &&
      t.isIdentifier(node.property, { name: 'session' })
    ) {
      hasSession = true;
    }
  });

  return hasSession || hasSessionImport;
}

/**
 * Phase 3: Detect JWT verification in middleware (existing function, kept for context)
 */
function detectJWTVerification(fn: t.Function, fileImports: string[]): {
  hasJWT: boolean;
  verifyMethod: string | null;
} {
  let hasJWT = false;
  let verifyMethod: string | null = null;

  // Check if file imports JWT library
  const hasJWTImport = fileImports.some(imp =>
    JWT_LIBRARIES.has(imp) || imp.includes('jwt')
  );

  if (!hasJWTImport) {
    return { hasJWT: false, verifyMethod: null };
  }

  // Look for JWT verification calls
  t.traverseFast(fn.body, node => {
    if (t.isCallExpression(node)) {
      // Pattern: jwt.verify()
      if (
        t.isMemberExpression(node.callee) &&
        t.isIdentifier(node.callee.object, { name: 'jwt' }) &&
        t.isIdentifier(node.callee.property)
      ) {
        const method = node.callee.property.name;
        if (JWT_VERIFY_PATTERNS.includes(method)) {
          hasJWT = true;
          verifyMethod = method;
        }
      }

      // Pattern: verify() direct call
      if (t.isIdentifier(node.callee)) {
        const method = node.callee.name;
        if (JWT_VERIFY_PATTERNS.includes(method)) {
          hasJWT = true;
          verifyMethod = method;
        }
      }
    }
  });

  return { hasJWT, verifyMethod };
}

/**
 * Phase 3: Detect error handling in auth middleware
 */
function hasErrorHandling(fn: t.Function): boolean {
  let hasHandler = false;

  t.traverseFast(fn.body, node => {
    // Try-catch blocks
    if (t.isTryStatement(node)) {
      hasHandler = true;
    }

    // Error responses (res.status(401/403))
    if (
      t.isCallExpression(node) &&
      t.isMemberExpression(node.callee) &&
      t.isCallExpression(node.callee.object) &&
      t.isMemberExpression(node.callee.object.callee) &&
      t.isIdentifier(node.callee.object.callee.object, { name: 'res' }) &&
      t.isIdentifier(node.callee.object.callee.property, { name: 'status' })
    ) {
      const statusArg = node.callee.object.arguments[0];
      if (
        t.isNumericLiteral(statusArg) &&
        (statusArg.value === 401 || statusArg.value === 403)
      ) {
        hasHandler = true;
      }
    }
  });

  return hasHandler;
}

/**
 * Phase 3: Enhanced function reference extraction
 */
function extractFunctionReference(
  node: t.Node,
  fileImports: string[]
): FunctionReference {
  if (t.isArrowFunctionExpression(node) || t.isFunctionExpression(node)) {
    const referencesUser = containsReqUser(node);
    const callsNext = detectNextCall(node);
    const conditionalAuth = detectConditionalAuth(node);
    const rolesChecked = extractRoles(node);
    const jwtInfo = detectJWTVerification(node, fileImports);
    const hasPassport = detectPassportAuth(node, fileImports);
    const hasSession = detectSessionUsage(node, fileImports);
    const errorHandling = hasErrorHandling(node);

    return {
      name: '<inline>',
      type: 'inline',
      isAsync: !!node.async,
      referencesUser,
      callsNext,
      conditionalAuth,
      rolesChecked,
      hasJWTVerification: jwtInfo.hasJWT || hasPassport,
      jwtVerifyMethod: jwtInfo.verifyMethod || (hasPassport ? 'passport' : null),
      hasErrorHandling: errorHandling || hasPassport || hasSession,
    };
  }

  if (t.isIdentifier(node)) {
    return {
      name: node.name,
      type: 'identifier',
      isAsync: false,
      referencesUser: false,
      callsNext: false,
      conditionalAuth: false,
      rolesChecked: [],
      hasJWTVerification: false,
      jwtVerifyMethod: null,
      hasErrorHandling: false,
    };
  }

  return {
    name: '<unknown>',
    type: 'unknown',
    isAsync: false,
    referencesUser: false,
    callsNext: false,
    conditionalAuth: false,
    rolesChecked: [],
    hasJWTVerification: false,
    jwtVerifyMethod: null,
    hasErrorHandling: false,
  };
}

/**
 * Main route extraction with Phase 3 enhancements
 */
export function extractExpressRoutes(
  ast: File,
  filePath: string
): RouteDefinition[] {
  const routes: RouteDefinition[] = [];
  const fileImports = extractImports(ast);

  traverseFn(ast, {
    CallExpression(path: any) {
      const { node } = path;

      if (!t.isMemberExpression(node.callee)) return;
      if (!t.isIdentifier(node.callee.property)) return;

      const method = node.callee.property.name;
      if (!HTTP_METHODS.has(method)) return;

      if (!t.isIdentifier(node.callee.object)) return;

      // Only string literal paths (no regex/params yet)
      const firstArg = node.arguments[0];
      if (!t.isStringLiteral(firstArg)) return;

      const handlers = node.arguments.slice(1);
      if (handlers.length === 0) return;

      const middleware: FunctionReference[] = [];
      let handler: FunctionReference | null = null;

      // Flatten nested middleware arrays: [auth, [validate, log]] -> [auth, validate, log]
      const flattenedHandlers: (t.Expression | t.SpreadElement)[] = [];
      handlers.forEach((arg: any) => {
        if (t.isArrayExpression(arg)) {
          flattenedHandlers.push(...arg.elements.filter((e): e is t.Expression | t.SpreadElement => e !== null));
        } else {
          flattenedHandlers.push(arg);
        }
      });

      flattenedHandlers.forEach((arg: any, index: number) => {
        const ref = extractFunctionReference(arg, fileImports);
        if (index === flattenedHandlers.length - 1 && method !== 'use') {
          handler = ref;
        } else {
          middleware.push(ref);
        }
      });

      // For app.use(), all are considered middleware if no explicit handler identified
      if (!handler && method !== 'use') return;
      if (!handler && method === 'use' && middleware.length > 0) {
        handler = middleware.pop()!;
      }

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