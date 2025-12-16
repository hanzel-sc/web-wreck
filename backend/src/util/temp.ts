/**
 * Temporary directory utilities
 * Stores temp data inside the current repository
 */

import * as fs from 'fs';
import * as path from 'path';

/**
 * Create a temporary directory inside the project
 */
export function createTempDir(): string {
  const projectRoot = process.cwd(); // where CLI was run
  const baseDir = path.join(projectRoot, '.web-wreck');
  const prefix = 'tmp-';
  const randomSuffix = Math.random().toString(36).slice(2);

  const tmpDir = path.join(baseDir, `${prefix}${randomSuffix}`);

  fs.mkdirSync(tmpDir, { recursive: true });
  return tmpDir;
}

/**
 * Cleanup temporary directory
 */
export function cleanupTempDir(tmpDir: string): void {
  if (fs.existsSync(tmpDir)) {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}
