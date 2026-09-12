/**
 * Cross-file import resolution
 * Resolves function references across module boundaries to enable
 * deep auth analysis on imported middleware/handlers.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as babelParser from '@babel/parser';
import traverse from '@babel/traverse';
import * as t from '@babel/types';
import type { File } from '@babel/types';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const traverseFn: (ast: File, visitors: Record<string, (path: any) => void>) => void =
  typeof (traverse as any).default === 'function'
    ? (traverse as any).default
    : traverse as any;

const BABEL_PLUGINS: babelParser.ParserPlugin[] = [
  'typescript', 'jsx', 'decorators-legacy', 'classProperties',
  'objectRestSpread', 'asyncGenerators', 'dynamicImport',
  'optionalChaining', 'nullishCoalescingOperator',
];

export interface ResolvedFunction {
  name: string;
  node: t.Function;
  filePath: string;
  fileImports: string[];
}

interface ImportMapping {
  localName: string;
  importedName: string;
  source: string;
}

/**
 * Cross-file function resolver
 * Parses all project files and builds an index of function declarations/exports
 * to resolve identifier references during route extraction.
 */
export class FunctionResolver {
  private fileASTs: Map<string, File> = new Map();
  private fileFunctions: Map<string, Map<string, t.Function>> = new Map();
  private fileImportsCache: Map<string, string[]> = new Map();

  constructor(private allFilePaths: string[]) {}

  /**
   * Index all files: parse ASTs and extract function declarations
   */
  indexFiles(): void {
    for (const filePath of this.allFilePaths) {
      try {
        const source = fs.readFileSync(filePath, 'utf-8');
        const ast = babelParser.parse(source, {
          sourceType: 'module',
          allowImportExportEverywhere: true,
          plugins: BABEL_PLUGINS,
        });
        this.fileASTs.set(filePath, ast);
        this.fileFunctions.set(filePath, this.extractFunctions(ast));
        this.fileImportsCache.set(filePath, this.extractImportSources(ast));
      } catch {
        // Skip files that can't be parsed
      }
    }
  }

  /**
   * Get the cached AST for a file (avoids re-parsing)
   */
  getAST(filePath: string): File | undefined {
    return this.fileASTs.get(filePath);
  }

  /**
   * Get cached import sources for a file
   */
  getFileImports(filePath: string): string[] {
    return this.fileImportsCache.get(filePath) ?? [];
  }

  /**
   * Resolve a function by name from a given file context.
   * First checks local declarations, then follows imports.
   */
  resolveFunction(name: string, fromFilePath: string): ResolvedFunction | null {
    // 1. Check local declarations in the current file
    const localFns = this.fileFunctions.get(fromFilePath);
    if (localFns?.has(name)) {
      const node = localFns.get(name);
      if (node) {
        return {
          name,
          node,
          filePath: fromFilePath,
          fileImports: this.fileImportsCache.get(fromFilePath) ?? [],
        };
      }
    }

    // 2. Check imports and resolve cross-file
    const ast = this.fileASTs.get(fromFilePath);
    if (!ast) return null;

    const importMapping = this.findImportMapping(name, ast);
    if (!importMapping) return null;

    // 3. Resolve the import source to a file path
    const resolvedPath = this.resolveModulePath(importMapping.source, fromFilePath);
    if (!resolvedPath) return null;

    // 4. Find the function in the resolved file
    const targetFns = this.fileFunctions.get(resolvedPath);
    if (!targetFns) return null;

    // Try the imported name first, then the local name
    const lookupName = importMapping.importedName === 'default'
      ? this.findDefaultExportName(resolvedPath)
      : importMapping.importedName;

    if (lookupName && targetFns.has(lookupName)) {
      const node = targetFns.get(lookupName);
      if (node) {
        return {
          name: lookupName,
          node,
          filePath: resolvedPath,
          fileImports: this.fileImportsCache.get(resolvedPath) ?? [],
        };
      }
    }

    return null;
  }

  /**
   * Resolve a function locally within a specific AST (same-file resolution)
   */
  resolveLocal(name: string, filePath: string): t.Function | null {
    const fns = this.fileFunctions.get(filePath);
    return fns?.get(name) ?? null;
  }

  /**
   * Extract all function declarations and expressions from an AST
   */
  private extractFunctions(ast: File): Map<string, t.Function> {
    const functions = new Map<string, t.Function>();

    traverseFn(ast, {
      // function foo(req, res, next) { ... }
      FunctionDeclaration(nodePath: { node: t.FunctionDeclaration }) {
        if (nodePath.node.id) {
          functions.set(nodePath.node.id.name, nodePath.node);
        }
      },
      // const foo = (req, res, next) => { ... }
      // const foo = function(req, res, next) { ... }
      VariableDeclarator(nodePath: { node: t.VariableDeclarator }) {
        if (
          t.isIdentifier(nodePath.node.id) &&
          nodePath.node.init &&
          (t.isArrowFunctionExpression(nodePath.node.init) ||
            t.isFunctionExpression(nodePath.node.init))
        ) {
          functions.set(nodePath.node.id.name, nodePath.node.init);
        }
      },
      // module.exports.foo = function(...) { ... }
      AssignmentExpression(nodePath: { node: t.AssignmentExpression }) {
        const { left, right } = nodePath.node;
        if (
          t.isMemberExpression(left) &&
          t.isIdentifier(left.property) &&
          (t.isArrowFunctionExpression(right) || t.isFunctionExpression(right))
        ) {
          // exports.foo = function() {} or module.exports.foo = function() {}
          if (
            t.isIdentifier(left.object, { name: 'exports' }) ||
            (t.isMemberExpression(left.object) &&
              t.isIdentifier(left.object.object, { name: 'module' }) &&
              t.isIdentifier(left.object.property, { name: 'exports' }))
          ) {
            functions.set(left.property.name, right);
          }
        }
      },
    });

    return functions;
  }

  /**
   * Extract import source module names from an AST
   */
  private extractImportSources(ast: File): string[] {
    const imports: string[] = [];
    traverseFn(ast, {
      ImportDeclaration(nodePath: { node: t.ImportDeclaration }) {
        imports.push(nodePath.node.source.value);
      },
      CallExpression(nodePath: { node: t.CallExpression }) {
        const { node } = nodePath;
        if (
          t.isIdentifier(node.callee, { name: 'require' }) &&
          node.arguments.length === 1 &&
          t.isStringLiteral(node.arguments[0])
        ) {
          imports.push(node.arguments[0].value);
        }
      },
    });
    return imports;
  }

  /**
   * Find the import mapping for a local name in the AST
   */
  private findImportMapping(name: string, ast: File): ImportMapping | null {
    let result: ImportMapping | null = null;

    traverseFn(ast, {
      // import { foo } from './bar'
      // import foo from './bar'
      ImportDeclaration(nodePath: { node: t.ImportDeclaration }) {
        for (const spec of nodePath.node.specifiers) {
          if (t.isImportSpecifier(spec) && t.isIdentifier(spec.local, { name })) {
            result = {
              localName: name,
              importedName: t.isIdentifier(spec.imported)
                ? spec.imported.name
                : name,
              source: nodePath.node.source.value,
            };
          }
          if (t.isImportDefaultSpecifier(spec) && t.isIdentifier(spec.local, { name })) {
            result = {
              localName: name,
              importedName: 'default',
              source: nodePath.node.source.value,
            };
          }
        }
      },
      // const { foo } = require('./bar')
      // const foo = require('./bar')
      VariableDeclarator(nodePath: { node: t.VariableDeclarator }) {
        const init = nodePath.node.init;
        if (!init) return;

        // const { foo } = require('./bar')
        if (
          t.isObjectPattern(nodePath.node.id) &&
          t.isCallExpression(init) &&
          t.isIdentifier(init.callee, { name: 'require' }) &&
          init.arguments.length === 1 &&
          t.isStringLiteral(init.arguments[0])
        ) {
          for (const prop of nodePath.node.id.properties) {
            if (
              t.isObjectProperty(prop) &&
              t.isIdentifier(prop.value, { name })
            ) {
              result = {
                localName: name,
                importedName: t.isIdentifier(prop.key) ? prop.key.name : name,
                source: init.arguments[0].value,
              };
            }
          }
        }

        // const foo = require('./bar')
        if (
          t.isIdentifier(nodePath.node.id, { name }) &&
          t.isCallExpression(init) &&
          t.isIdentifier(init.callee, { name: 'require' }) &&
          init.arguments.length === 1 &&
          t.isStringLiteral(init.arguments[0])
        ) {
          result = {
            localName: name,
            importedName: 'default',
            source: init.arguments[0].value,
          };
        }
      },
    });

    return result;
  }

  /**
   * Find the name of the default export in a file
   */
  private findDefaultExportName(filePath: string): string | null {
    const ast = this.fileASTs.get(filePath);
    if (!ast) return null;

    let name: string | null = null;

    traverseFn(ast, {
      ExportDefaultDeclaration(nodePath: { node: t.ExportDefaultDeclaration }) {
        const decl = nodePath.node.declaration;
        if (t.isFunctionDeclaration(decl) && decl.id) {
          name = decl.id.name;
        }
        if (t.isIdentifier(decl)) {
          name = decl.name;
        }
      },
      // module.exports = foo
      AssignmentExpression(nodePath: { node: t.AssignmentExpression }) {
        const { left, right } = nodePath.node;
        if (
          t.isMemberExpression(left) &&
          t.isIdentifier(left.object, { name: 'module' }) &&
          t.isIdentifier(left.property, { name: 'exports' }) &&
          t.isIdentifier(right)
        ) {
          name = right.name;
        }
      },
    });

    return name;
  }

  /**
   * Resolve a module specifier to an absolute file path
   */
  private resolveModulePath(source: string, fromFile: string): string | null {
    // Only resolve relative imports
    if (!source.startsWith('.')) return null;

    const dir = path.dirname(fromFile);
    const basePath = path.resolve(dir, source);

    // Try exact match
    if (this.fileASTs.has(basePath)) return basePath;

    // Try with extensions
    const extensions = ['.ts', '.js', '.tsx', '.jsx'];
    for (const ext of extensions) {
      const withExt = basePath + ext;
      if (this.fileASTs.has(withExt)) return withExt;
    }

    // Try index files
    for (const ext of extensions) {
      const indexPath = path.join(basePath, 'index' + ext);
      if (this.fileASTs.has(indexPath)) return indexPath;
    }

    return null;
  }
}
