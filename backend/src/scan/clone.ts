import { simpleGit, CleanOptions} from 'simple-git'
import type {SimpleGit} from 'simple-git';


import { createTempDir } from '../util/temp.js';

export async function cloneRepository(repoUrl: string): Promise<string> {
  const tmpDir = createTempDir();
  const git: SimpleGit = simpleGit();
  
  try {
    await git.clone(repoUrl, tmpDir, ['--depth', '1']);
    return tmpDir;
  } catch (error) {
    throw new Error(`Failed to clone repository: ${error}`);
  }
}