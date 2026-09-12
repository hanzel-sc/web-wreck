/**
 * Source ingestion orchestrator
 * Handles repository cloning and file discovery
 */

import { cloneRepository, validateRepoUrl } from './clone.js';
import type { CloneOptions } from './clone.js';
import { discoverSourceFiles } from './files.js';
import { log } from '../util/log.js';

export interface ScanResult {
  repoPath: string;
  files: string[];
}

export interface ScanOptions {
  insecure?: boolean;
}

/**
 * Main entry point for source ingestion phase
 */
export async function scanRepository(
  repoUrl: string,
  options: ScanOptions = {}
): Promise<ScanResult> {
  // Validate URL before attempting clone
  const validatedUrl = validateRepoUrl(repoUrl);

  log.info(`Cloning repository: ${validatedUrl}`);
  const cloneOpts: CloneOptions = { insecure: options.insecure };
  const repoPath = await cloneRepository(validatedUrl, cloneOpts);

  log.info(`Discovering source files in: ${repoPath}`);
  const files = discoverSourceFiles(repoPath);

  return { repoPath, files };
}