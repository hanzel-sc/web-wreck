/**
 * Express route extraction — Enhanced
 * Compiler-style frontend for Express routing with deep semantic analysis.
 * 
 * Features:
 * - Route definition extraction (app.get, router.post, etc.)
 * - Router mount point detection (app.use('/api', router))
 * - Global middleware detection (app.use(fn) without path)
 * - Cross-file function resolution for identifier references
 * - JWT/Passport/Session auth pattern detection
 * - RBAC and conditional auth analysis
 */

import traverse from '@babel/traverse';
import * as t from '@babel/types';
import type { File } from '@babel/types';
import type { RouteDefinition, FunctionReference } from './index.js';
import type { FunctionResolver } from './resolve.js';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const traverseFn: (ast: File, visitors: Record<string, (path: any) => void>) => void =
  typeof (traverse as any).default === 'function'
    ? (traverse as any).default
    : traverse as any;

const HTTP_METHODS = new Set([
  'get', 'post', 'put', 'delete', 'patch', 'use', 'all',
]);

// JWT library detection patterns
const JWT_LIBRARIES = new Set([
  'jsonwebtoken', 'express-jwt', 'jwt-simple',
  '@auth0/express-jwt', 'passport-jwt',
]);

const PASSPORT_LIBRARIES = new Set([
  'passport', 'passport-local', 'passport-http', 'passport-strategy',
]);

const SESSION_LIBRARIES = new Set([
  'express-session', 'cookie-session', 'connect-mongodb-session',
]);

// Common JWT validation patterns
const JWT_VERIFY_PATTERNS = [
  'verify', 'decode', 'validateToken', 'verifyToken', 'checkToken',
];

/** Mount point: app.use('/prefix', routerVar) */
export interface MountPoint {
  path: string;
  routerName: string;
  filePath: string;
  line: number;
}

/** Global middleware: app.use(fn) without a path */
export interface GlobalMiddlewareDefinition {
  ref: FunctionReference;
  filePath: string;
  line: number;
}

// ─── Auth pattern detection helpers ────────────────────────────────

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

function detectConditionalAuth(fn: t.Function): boolean {
  let found = false;
  t.traverseFast(fn.body, node => {
    if (t.isIfStatement(node)) {
      const test = node.test;
      if (
        t.isMemberExpression(test) &&
        t.isIdentifier(test.object, { name: 'req' }) &&
        t.isIdentifier(test.property, { name: 'user' })
      ) {
        found = true;
      }
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

function extractRoles(fn: t.Function): string[] {
  const roles: Set<string> = new Set();
  t.traverseFast(fn.body, node => {
    if (
      t.isMemberExpression(node) &&
      t.isMemberExpression(node.object) &&
      t.isIdentifier(node.object.object, { name: 'req' }) &&
      t.isIdentifier(node.object.property, { name: 'user' }) &&
      t.isIdentifier(node.property)
    ) {
      const roleProp = node.property.name;
      if (['role', 'roles', 'permissions', 'authorities'].includes(roleProp)) {
        roles.add(roleProp);
      }
    }
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

function detectPassportAuth(fn: t.Function, fileImports: string[]): boolean {
  let hasPassport = false;
  const hasPassportImport = fileImports.some(
    imp => PASSPORT_LIBRARIES.has(imp) || imp.includes('passport')
  );
  if (!hasPassportImport) return false;

  t.traverseFast(fn.body, node => {
    if (t.isCallExpression(node)) {
      if (
        t.isMemberExpression(node.callee) &&
        t.isIdentifier(node.callee.object, { name: 'passport' }) &&
        t.isIdentifier(node.callee.property, { name: 'authenticate' })
      ) {
        hasPassport = true;
      }
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

function detectSessionUsage(fn: t.Function, fileImports: string[]): boolean {
  let hasSession = false;
  const hasSessionImport = fileImports.some(
    imp => SESSION_LIBRARIES.has(imp) || imp.includes('session')
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

function detectJWTVerification(
  fn: t.Function,
  fileImports: string[]
): { hasJWT: boolean; verifyMethod: string | null } {
  let hasJWT = false;
  let verifyMethod: string | null = null;

  const hasJWTImport = fileImports.some(
    imp => JWT_LIBRARIES.has(imp) || imp.includes('jwt')
  );
  if (!hasJWTImport) return { hasJWT: false, verifyMethod: null };

  t.traverseFast(fn.body, node => {
    if (t.isCallExpression(node)) {
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

function hasErrorHandling(fn: t.Function): boolean {
  let hasHandler = false;
  t.traverseFast(fn.body, node => {
    if (t.isTryStatement(node)) {
      hasHandler = true;
    }
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

// ─── Function analysis ─────────────────────────────────────────────

/**
 * Analyze a function node for auth patterns and return a FunctionReference
 */
function analyzeFunctionNode(
  fn: t.Function,
  name: string,
  type: FunctionReference['type'],
  fileImports: string[]
): FunctionReference {
  const referencesUser = containsReqUser(fn);
  const callsNext = detectNextCall(fn);
  const conditionalAuth = detectConditionalAuth(fn);
  const rolesChecked = extractRoles(fn);
  const jwtInfo = detectJWTVerification(fn, fileImports);
  const hasPassport = detectPassportAuth(fn, fileImports);
  const hasSession = detectSessionUsage(fn, fileImports);
  const errorHandling = hasErrorHandling(fn);

  return {
    name,
    type,
    isAsync: !!fn.async,
    referencesUser,
    callsNext,
    conditionalAuth,
    rolesChecked,
    hasJWTVerification: jwtInfo.hasJWT || hasPassport,
    jwtVerifyMethod: jwtInfo.verifyMethod || (hasPassport ? 'passport' : null),
    hasErrorHandling: errorHandling || hasPassport || hasSession,
  };
}

/**
 * Extract function reference with cross-file resolution support
 */
function extractFunctionReference(
  node: t.Node,
  fileImports: string[],
  filePath: string,
  resolver?: FunctionResolver
): FunctionReference {
  // Inline function — analyze directly
  if (t.isArrowFunctionExpression(node) || t.isFunctionExpression(node)) {
    return analyzeFunctionNode(node, '<inline>', 'inline', fileImports);
  }

  // Identifier reference — try to resolve the function body
  if (t.isIdentifier(node)) {
    if (resolver) {
      const resolved = resolver.resolveFunction(node.name, filePath);
      if (resolved) {
        return analyzeFunctionNode(
          resolved.node,
          node.name,
          'identifier',
          resolved.fileImports
        );
      }
    }

    // Fallback: return name-only reference (no body analysis possible)
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

  // Call expression — e.g., passport.authenticate('local')
  if (t.isCallExpression(node)) {
    if (
      t.isMemberExpression(node.callee) &&
      t.isIdentifier(node.callee.object) &&
      t.isIdentifier(node.callee.property)
    ) {
      const name = `${node.callee.object.name}.${node.callee.property.name}`;
      const isPassportAuth =
        node.callee.object.name === 'passport' &&
        node.callee.property.name === 'authenticate';

      return {
        name,
        type: 'identifier',
        isAsync: false,
        referencesUser: false,
        callsNext: false,
        conditionalAuth: false,
        rolesChecked: [],
        hasJWTVerification: isPassportAuth,
        jwtVerifyMethod: isPassportAuth ? 'passport' : null,
        hasErrorHandling: isPassportAuth,
      };
    }
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

// ─── Import extraction ─────────────────────────────────────────────

function extractImports(ast: File): string[] {
  const imports: string[] = [];
  traverseFn(ast, {
    ImportDeclaration(path: { node: t.ImportDeclaration }) {
      imports.push(path.node.source.value);
    },
    CallExpression(path: { node: t.CallExpression }) {
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

// ─── Main route extraction ─────────────────────────────────────────

/**
 * Extract Express route definitions from an AST.
 * Supports both app.METHOD() and router.METHOD() patterns.
 */
export function extractExpressRoutes(
  ast: File,
  filePath: string,
  resolver?: FunctionResolver
): RouteDefinition[] {
  const routes: RouteDefinition[] = [];
  const fileImports = extractImports(ast);

  traverseFn(ast, {
    CallExpression(path: { node: t.CallExpression }) {
      const { node } = path;

      if (!t.isMemberExpression(node.callee)) return;
      if (!t.isIdentifier(node.callee.property)) return;

      const method = node.callee.property.name;
      if (!HTTP_METHODS.has(method)) return;

      // Support both simple identifiers (app, router) and member expressions (this.router)
      if (
        !t.isIdentifier(node.callee.object) &&
        !t.isMemberExpression(node.callee.object)
      ) {
        return;
      }

      // First argument must be a string literal path
      const firstArg = node.arguments[0];
      if (!firstArg || !t.isStringLiteral(firstArg)) return;

      const handlers = node.arguments.slice(1);
      if (handlers.length === 0) return;

      const middleware: FunctionReference[] = [];
      let handler: FunctionReference | null = null;

      // Flatten nested middleware arrays: [auth, [validate, log]] -> [auth, validate, log]
      const flattenedHandlers: (t.Expression | t.SpreadElement)[] = [];
      for (const arg of handlers) {
        if (t.isArrayExpression(arg)) {
          flattenedHandlers.push(
            ...arg.elements.filter(
              (e): e is t.Expression | t.SpreadElement => e !== null
            )
          );
        } else {
          flattenedHandlers.push(arg as t.Expression | t.SpreadElement);
        }
      }

      for (let idx = 0; idx < flattenedHandlers.length; idx++) {
        const arg = flattenedHandlers[idx];
        if (!arg) continue;
        const ref = extractFunctionReference(arg, fileImports, filePath, resolver);
        if (idx === flattenedHandlers.length - 1 && method !== 'use') {
          handler = ref;
        } else {
          middleware.push(ref);
        }
      }

      // For app.use(), all are considered middleware if no explicit handler
      if (!handler && method !== 'use') return;
      if (!handler && method === 'use' && middleware.length > 0) {
        handler = middleware.pop() ?? null;
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

// ─── Mount point extraction ────────────────────────────────────────

/**
 * Extract Router mount points: app.use('/prefix', routerVariable)
 * These are used to compose full paths for routes defined in sub-routers.
 */
export function extractMountPoints(ast: File, filePath: string): MountPoint[] {
  const mountPoints: MountPoint[] = [];

  // First, detect which variables are express.Router() instances
  const routerVars = new Set<string>();
  traverseFn(ast, {
    VariableDeclarator(path: { node: t.VariableDeclarator }) {
      if (
        t.isIdentifier(path.node.id) &&
        t.isCallExpression(path.node.init) &&
        t.isMemberExpression(path.node.init.callee) &&
        t.isIdentifier(path.node.init.callee.property, { name: 'Router' })
      ) {
        routerVars.add(path.node.id.name);
      }
    },
  });

  // Find app.use('/path', routerVar) patterns
  traverseFn(ast, {
    CallExpression(path: { node: t.CallExpression }) {
      const { node } = path;
      if (!t.isMemberExpression(node.callee)) return;
      if (!t.isIdentifier(node.callee.property, { name: 'use' })) return;
      if (node.arguments.length < 2) return;

      const pathArg = node.arguments[0];
      const routerArg = node.arguments[1];

      if (
        t.isStringLiteral(pathArg) &&
        routerArg &&
        t.isIdentifier(routerArg)
      ) {
        // Only record as mount point if:
        // - The identifier is a known Router variable, OR
        // - The identifier name suggests it's a router (contains 'route' or 'router')
        const isRouter =
          routerVars.has(routerArg.name) ||
          routerArg.name.toLowerCase().includes('route') ||
          routerArg.name.toLowerCase().includes('router');

        if (isRouter) {
          mountPoints.push({
            path: pathArg.value,
            routerName: routerArg.name,
            filePath,
            line: node.loc?.start.line ?? 0,
          });
        }
      } else if (node.arguments.length === 1 && pathArg && t.isIdentifier(pathArg)) {
        // Pattern: app.use(authRoutes) mounted at root
        const isRouter =
          routerVars.has(pathArg.name) ||
          pathArg.name.toLowerCase().includes('route') ||
          pathArg.name.toLowerCase().includes('router');

        if (isRouter) {
          mountPoints.push({
            path: '',
            routerName: pathArg.name,
            filePath,
            line: node.loc?.start.line ?? 0,
          });
        }
      }
    },
  });

  return mountPoints;
}

// ─── Global middleware extraction ──────────────────────────────────

/**
 * Extract global middleware: app.use(fn) without a path argument.
 * These are middleware applied to ALL routes.
 */
export function extractGlobalMiddleware(
  ast: File,
  filePath: string,
  resolver?: FunctionResolver
): GlobalMiddlewareDefinition[] {
  const globals: GlobalMiddlewareDefinition[] = [];
  const fileImports = extractImports(ast);

  // Collect router variables in this file
  const routerVars = new Set<string>();
  traverseFn(ast, {
    VariableDeclarator(path: { node: t.VariableDeclarator }) {
      if (
        t.isIdentifier(path.node.id) &&
        path.node.init &&
        t.isCallExpression(path.node.init) &&
        t.isMemberExpression(path.node.init.callee) &&
        t.isIdentifier(path.node.init.callee.property, { name: 'Router' })
      ) {
        routerVars.add(path.node.id.name);
      }
    },
  });

  traverseFn(ast, {
    CallExpression(path: { node: t.CallExpression }) {
      const { node } = path;
      if (!t.isMemberExpression(node.callee)) return;
      if (!t.isIdentifier(node.callee.property, { name: 'use' })) return;
      if (!t.isIdentifier(node.callee.object)) return;

      // app.use(fn) — first arg is NOT a string, so it's a global middleware
      if (node.arguments.length === 0) return;
      const firstArg = node.arguments[0];
      if (!firstArg || t.isStringLiteral(firstArg)) return;

      // If it's a router mounted without a path (e.g., app.use(authRoutes)), skip as middleware
      if (t.isIdentifier(firstArg)) {
        const name = firstArg.name.toLowerCase();
        if (
          routerVars.has(firstArg.name) ||
          name.endsWith('routes') ||
          name.endsWith('router') ||
          name.includes('route')
        ) {
          return;
        }
      }

      // It's a global middleware application
      const ref = extractFunctionReference(firstArg, fileImports, filePath, resolver);
      globals.push({
        ref,
        filePath,
        line: node.loc?.start.line ?? 0,
      });
    },
  });

  return globals;
}