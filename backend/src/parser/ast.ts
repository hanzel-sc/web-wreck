/**
 * AST parsing utilities using Babel
 */

import * as fs from 'fs';
import * as parser from '@babel/parser';
import type { File } from '@babel/types';

/**
 * Parse a JavaScript/TypeScript file into a Babel AST
 */
export function parseFileToAST(filePath: string): File {
  const source = fs.readFileSync(filePath, 'utf-8');
  
  // Parse with plugins for common syntax extensions
  return parser.parse(source, {
    sourceType: 'module',
    allowImportExportEverywhere: true,
    plugins: [
      'typescript',
      'jsx',
      'decorators-legacy',
      'classProperties',
      'objectRestSpread',
      'asyncGenerators',
      'dynamicImport',
      'optionalChaining',
      'nullishCoalescingOperator',
    ],
  });
}