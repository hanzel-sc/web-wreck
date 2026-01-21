/**
 * Parsing orchestrator - Phase 3 Enhanced
 * Compiler-style frontend coordinator with auth semantics
 */

import { parseFileToAST } from './ast.js';
import { extractExpressRoutes } from './express.js';
import { log } from '../util/log.js';

export interface ParsedFile {
  filePath: string;
  routes: RouteDefinition[];
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
 * Phase 3: Enhanced function reference with auth semantics
 */
export interface FunctionReference {
  name: string;
  type: 'inline' | 'identifier' | 'unknown';
  isAsync: boolean;
  
  // Basic auth detection
  referencesUser: boolean;
  callsNext: boolean;
  
  // Phase 3: Conditional auth patterns
  conditionalAuth: boolean;
  
  // Phase 3: RBAC detection
  rolesChecked: string[];
  
  // Phase 3: JWT verification
  hasJWTVerification: boolean;
  jwtVerifyMethod: string | null;
  
  // Phase 3: Error handling
  hasErrorHandling: boolean;
}

export async function parseFiles(
  filePaths: string[]
): Promise<ParsedFile[]> {
  const results: ParsedFile[] = [];

  for (const filePath of filePaths) {
    try {
      const ast = parseFileToAST(filePath);
      const routes = extractExpressRoutes(ast, filePath);

      if (routes.length > 0) {
        results.push({ filePath, routes });
      }
    } catch (err) {
      log.warn(`Skipping ${filePath}: ${String(err)}`);
    }
  }

  return results;
}