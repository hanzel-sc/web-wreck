/**
 * Parsing orchestrator — Enhanced
 * Coordinates AST parsing, route extraction, cross-file resolution,
 * Router mount path composition, and global middleware tracking.
 */

import { parseFileToAST } from './ast.js';
import { extractExpressRoutes, extractMountPoints, extractGlobalMiddleware } from './express.js';
import type { MountPoint, GlobalMiddlewareDefinition } from './express.js';
import { FunctionResolver } from './resolve.js';
import { log } from '../util/log.js';
import * as path from 'path';

export interface ParsedFile {
  filePath: string;
  routes: RouteDefinition[];
}

export interface ParseResult {
  parsedFiles: ParsedFile[];
  mountPoints: MountPoint[];
  globalMiddleware: GlobalMiddlewareDefinition[];
}

export interface RouteDefinition {
  method: string;
  path: string;
  filePath: string;
  line: number;
  middleware: FunctionReference[];
  handler: FunctionReference;
  fileImports: string[];
}

/**
 * Enhanced function reference with auth semantics
 */
export interface FunctionReference {
  name: string;
  type: 'inline' | 'identifier' | 'unknown';
  isAsync: boolean;

  // Basic auth detection
  referencesUser: boolean;
  callsNext: boolean;

  // Conditional auth patterns
  conditionalAuth: boolean;

  // RBAC detection
  rolesChecked: string[];

  // JWT verification
  hasJWTVerification: boolean;
  jwtVerifyMethod: string | null;

  // Error handling
  hasErrorHandling: boolean;
}

/**
 * Parse all files with cross-file resolution and mount path composition
 */
export async function parseFiles(
  filePaths: string[]
): Promise<ParseResult> {
  // Step 1: Build the cross-file function resolver index
  log.info('Building cross-file function index...');
  const resolver = new FunctionResolver(filePaths);
  resolver.indexFiles();

  // Step 2: Extract routes, mount points, and global middleware from each file
  const parsedFiles: ParsedFile[] = [];
  const allMountPoints: MountPoint[] = [];
  const allGlobalMiddleware: GlobalMiddlewareDefinition[] = [];

  for (const filePath of filePaths) {
    try {
      const ast = resolver.getAST(filePath) ?? parseFileToAST(filePath);
      const routes = extractExpressRoutes(ast, filePath, resolver);
      const mounts = extractMountPoints(ast, filePath);
      const globalMw = extractGlobalMiddleware(ast, filePath, resolver);

      if (routes.length > 0) {
        parsedFiles.push({ filePath, routes });
      }

      allMountPoints.push(...mounts);
      allGlobalMiddleware.push(...globalMw);
    } catch (err) {
      log.warn(`Skipping ${filePath}: ${String(err)}`);
    }
  }

  // Step 3: Compose mount paths with router routes
  composeMountPaths(parsedFiles, allMountPoints, resolver);

  return {
    parsedFiles,
    mountPoints: allMountPoints,
    globalMiddleware: allGlobalMiddleware,
  };
}

/**
 * Compose mount paths with Router routes.
 * When we see app.use('/api', userRouter) and userRouter is imported from
 * a file containing router.get('/users', ...), compose to '/api/users'.
 */
function composeMountPaths(
  parsedFiles: ParsedFile[],
  mountPoints: MountPoint[],
  resolver: FunctionResolver
): void {
  for (const mount of mountPoints) {
    // Try to resolve which file the mounted router comes from
    const resolved = resolver.resolveFunction(mount.routerName, mount.filePath);
    const routerFilePath = resolved?.filePath;

    // Also check if the router variable matches a file that was parsed
    // (common pattern: const userRouter = require('./routes/users'))
    for (const parsed of parsedFiles) {
      const isMatch = routerFilePath
        ? parsed.filePath === routerFilePath
        : parsed.filePath.includes(mount.routerName);

      if (isMatch && mount.path !== '/') {
        // Compose the mount prefix with each route's path
        for (const route of parsed.routes) {
          if (!route.path.startsWith(mount.path)) {
            const composed = normalizePath(mount.path + route.path);
            log.info(`Path composition: ${mount.path} + ${route.path} → ${composed}`);
            route.path = composed;
          }
        }
      }
    }
  }
}

/**
 * Normalize a composed path (remove double slashes, ensure leading slash)
 */
function normalizePath(p: string): string {
  return '/' + p.replace(/\/+/g, '/').replace(/^\/+/, '').replace(/\/+$/, '');
}