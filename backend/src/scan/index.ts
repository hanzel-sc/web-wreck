/**
 * Source ingestion orchestrator
 * Handles repository cloning and file discovery
 */

import { cloneRepository } from './clone.js';
import { discoverSourceFiles } from './files.js';
import { log } from '../util/log.js';

export interface ScanResult {
  repoPath: string;
  files: string[];
}

/**
 * Main entry point for source ingestion phase
 */
export async function scanRepository(repoUrl: string): Promise<ScanResult> {
  log.info(`Cloning repository: ${repoUrl}`);
  const repoPath = await cloneRepository(repoUrl);
  
  log.info(`Discovering source files in: ${repoPath}`);
  const files = discoverSourceFiles(repoPath);
  
  return { repoPath, files };
}