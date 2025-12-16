/**
 * Parsing orchestrator
 * Compiler-style frontend coordinator
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

export interface FunctionReference {
  name: string;
  type: 'inline' | 'identifier' | 'unknown';
  isAsync: boolean;
  referencesUser: boolean;
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
