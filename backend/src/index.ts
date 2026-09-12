#!/usr/bin/env node

/**
 * Web-Wreck v0.1.0
 * Compiler-style static analysis tool for Express route security
 * 
 * Pipeline:
 * 1. Source ingestion (clone + file discovery)
 * 2. Parsing (AST construction + cross-file resolution)
 * 3. IR building (execution graph + global middleware)
 * 4. Analysis (auth detection + findings)
 * 5. Output (JSON + Mermaid + HTML + MD)
 */

import { Command } from 'commander';
import { scanRepository } from './scan/index.js';
import { parseFiles } from './parser/index.js';
import { buildExecutionGraph } from './ir/build.js';
import { analyzeAuthPresence, generateSecurityReport, generateFindingReport, exportFindingsMarkdown } from './analyze/index.js';
import { outputJson, outputMermaid } from './graph/index.js';
import { outputHtml } from './output/visualize.js';
import { log } from './util/log.js';
import { cleanupTempDir } from './util/temp.js';

import * as fs from 'fs';
import * as path from 'path';

const VERSION = '0.1.0';

const program = new Command();

program
  .name('web-wreck')
  .description('Static analysis tool for mapping authentication and authorization flows in Express.js applications')
  .version(VERSION)
  .argument('<repo-url>', 'Public GitHub repository URL to analyze')
  .option('--insecure', 'Disable SSL certificate verification for git clone (useful behind corporate proxies)')
  .option('-o, --output <dir>', 'Output directory for reports', 'web-wreck-output')
  .option('--json-only', 'Output JSON to stdout only (CI-friendly mode)')
  .option('--no-html', 'Skip HTML report generation')
  .option('-v, --verbose', 'Enable verbose logging')
  .action(async (repoUrl: string, options: {
    insecure?: boolean;
    output: string;
    jsonOnly?: boolean;
    html?: boolean;
    verbose?: boolean;
  }) => {
    console.log(`Web-Wreck v${VERSION} - Express Route Security Analyzer\n`);

    let repoPath: string | null = null;

    try {
      // Phase 1: Source ingestion
      log.phase('Source Ingestion');
      const scanResult = await scanRepository(repoUrl, {
        insecure: options.insecure,
      });
      repoPath = scanResult.repoPath;
      const { files } = scanResult;
      log.success(`Discovered ${files.length} source files`);

      // Phase 2: Parsing (with cross-file resolution)
      log.phase('AST Parsing');
      const parseResult = await parseFiles(files);
      const { parsedFiles, globalMiddleware, mountPoints } = parseResult;
      log.success(`Parsed ${parsedFiles.length} files with routes`);
      if (globalMiddleware.length > 0) {
        log.info(`Detected ${globalMiddleware.length} global middleware`);
      }
      if (mountPoints.length > 0) {
        log.info(`Detected ${mountPoints.length} Router mount points`);
      }

      // Phase 3: IR construction (with global middleware)
      log.phase('IR Construction');
      const graph = buildExecutionGraph(parsedFiles, globalMiddleware);
      log.success(`Built graph with ${graph.routes.length} routes, ${graph.nodes.size} nodes`);

      // Phase 4: Analysis
      log.phase('Security Analysis');
      const analysis = analyzeAuthPresence(graph);
      const report = generateSecurityReport(graph, analysis);
      log.success(`Risk Score: ${report.summary.riskScore}/100 - ${report.overallStatus}`);
      log.success(`Found ${report.prioritizedFindings.length} security issues`);

      if (analysis.globalAuthMiddleware.length > 0) {
        log.info(`${analysis.globalAuthMiddleware.length} global auth middleware detected`);
      }

      // Phase 5: Output
      log.phase('Output Generation');

      // JSON output
      const jsonOutput = outputJson(graph, analysis, report, repoUrl);

      if (options.jsonOnly) {
        // CI-friendly: only JSON to stdout
        console.log(JSON.stringify(jsonOutput, null, 2));
        return;
      }

      // Generate all output formats
      const mermaidOutput = outputMermaid(graph, analysis);
      const findingsReport = generateFindingReport(graph, analysis);
      const markdownReport = exportFindingsMarkdown(findingsReport);

      // Write output files
      const outputDir = path.resolve(options.output);
      if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
      }

      const timestamp = new Date().toISOString().replace(/[:.]/g, '-').split('T')[0];
      const fileid = Math.random().toString(36).substring(2, 8);

      const mdPath = path.join(outputDir, `report-${timestamp}-${fileid}.md`);
      fs.writeFileSync(mdPath, markdownReport, 'utf-8');

      if (options.html !== false) {
        const htmlOutput = outputHtml(graph, analysis, report, repoUrl);
        const htmlPath = path.join(outputDir, `report-${timestamp}-${fileid}.html`);
        fs.writeFileSync(htmlPath, htmlOutput, 'utf-8');
        console.log(`\n[✓] HTML report: ${htmlPath}`);
      }

      console.log(`[✓] Markdown report: ${mdPath}`);

      if (options.verbose) {
        console.log('\n=== JSON Output ===');
        console.log(JSON.stringify(jsonOutput, null, 2));
        console.log('\n=== Mermaid Diagram ===');
        console.log(mermaidOutput);
      }

      log.success('Analysis complete');

    } catch (error: unknown) {
      log.error('Analysis failed', error);
      process.exit(1);
    } finally {
      // Always cleanup temporary directory
      if (repoPath) {
        try {
          cleanupTempDir(repoPath);
          if (options.verbose) {
            log.info(`Cleaned up temporary directory: ${repoPath}`);
          }
        } catch {
          // Cleanup failure is non-fatal
        }
      }
    }
  });

program.parse();