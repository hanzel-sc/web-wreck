/**
 * Source file discovery
 * Walks directory tree and collects JS/TS files
 */

import * as fs from 'fs';
import * as path from 'path';

// Directories to ignore during traversal
const IGNORE_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  'coverage',
  '.next',
  'out',
  'frontend',
  'public',
  'static',
  'assets'
]);

// File extensions to collect
const SOURCE_EXTENSIONS = new Set(['.js', '.ts', '.jsx', '.tsx']);

/**
 * Recursively discover all source files in a directory
 */
export function discoverSourceFiles(rootPath: string): string[] {
  const results: string[] = [];
  
  function walk(dir: string) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      
      if (entry.isDirectory()) {
        // Skip ignored directories
        if (IGNORE_DIRS.has(entry.name)) {
          continue;
        }
        walk(fullPath);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name);
        if (SOURCE_EXTENSIONS.has(ext)) {
          results.push(fullPath);
        }
      }
    }
  }
  
  walk(rootPath);
  return results;
}