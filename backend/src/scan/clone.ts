/**
 * Repository cloning with SSL error handling and URL validation
 */

import { simpleGit } from 'simple-git';
import type { SimpleGit } from 'simple-git';
import { createTempDir } from '../util/temp.js';

/** Valid GitHub URL pattern */
const GITHUB_URL_PATTERN = /^https?:\/\/(www\.)?github\.com\/[\w.-]+\/[\w.-]+(\.git)?$/i;

/**
 * Validate and sanitize a GitHub repository URL
 */
export function validateRepoUrl(url: string): string {
  const trimmed = url.trim();

  if (!trimmed) {
    throw new Error('Repository URL cannot be empty');
  }

  // Basic URL format check
  try {
    new URL(trimmed);
  } catch {
    throw new Error(`Invalid URL format: ${trimmed}`);
  }

  // GitHub-specific validation
  if (!GITHUB_URL_PATTERN.test(trimmed)) {
    throw new Error(
      `Invalid GitHub repository URL: ${trimmed}\n` +
      `Expected format: https://github.com/owner/repo`
    );
  }

  return trimmed;
}

export interface CloneOptions {
  insecure?: boolean;
}

export async function cloneRepository(
  repoUrl: string,
  options: CloneOptions = {}
): Promise<string> {
  const tmpDir = createTempDir();
  const git: SimpleGit = simpleGit();

  // Disable SSL verification if requested (for corporate proxies, etc.)
  if (options.insecure) {
    git.env('GIT_SSL_NO_VERIFY', 'true');
  }

  try {
    await git.clone(repoUrl, tmpDir, ['--depth', '1']);
    return tmpDir;
  } catch (error: unknown) {
    const errorMsg = String(error);

    // Detect SSL errors and suggest --insecure flag
    if (errorMsg.includes('SSL certificate problem') || errorMsg.includes('ssl')) {
      throw new Error(
        `SSL certificate error while cloning.\n` +
        `This often happens behind corporate proxies or VPNs.\n` +
        `Try running with --insecure flag to bypass SSL verification:\n` +
        `  web-wreck ${repoUrl} --insecure`
      );
    }

    throw new Error(`Failed to clone repository: ${error}`);
  }
}