#!/usr/bin/env node

/**
 * Web-Wreck v0.0.2
 * Compiler-style static analysis tool for Express route security
 * 
 * Pipeline:
 * 1. Source ingestion (clone + file discovery)
 * 2. Parsing (AST construction)
 * 3. IR building (execution graph)
 * 4. Analysis (auth detection)
 * 5. Output (JSON + Mermaid + HTML + MD)
 */

import { scanRepository } from './scan/index.js';
import { parseFiles } from './parser/index.js';
import { buildExecutionGraph } from './ir/build.js';
import { analyzeAuthPresence, generateSecurityReport, generateFindingReport, exportFindingsMarkdown } from './analyze/index.js';
import { outputJson, outputMermaid } from './graph/index.js';
import { outputHtml } from './output/visualize.js';
import { log } from './util/log.js';

import * as fs from 'fs';
import * as path from 'path';

async function main() {

  console.log('Web-Wreck v0.0.2 - Express Route Security Analyzer\n');
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.error('Usage: web-wreck <github-repo-url>');
    console.error('Example: web-wreck https://github.com/username/express-app');
    process.exit(1);
  }

  const repoUrl = args[0];

  try {
    // Phase 1: Source ingestion
    log.phase('Source Ingestion');
    const { repoPath, files } = await scanRepository(repoUrl);
    log.success(`Discovered ${files.length} source files`);

    // Phase 2: Parsing
    log.phase('AST Parsing');
    const parsedFiles = await parseFiles(files);
    log.success(`Parsed ${parsedFiles.length} files successfully`);

    // Phase 3: IR construction
    log.phase('IR Construction');
    const graph = buildExecutionGraph(parsedFiles);
    log.success(`Built graph with ${graph.routes.length} routes`);

    // Phase 4: Analysis
    log.phase('Security Analysis');
    const analysis = analyzeAuthPresence(graph);

    // Phase 4: Security Reporting
    const report = generateSecurityReport(graph, analysis);
    log.success(`Risk Score: ${report.summary.riskScore}/100 - ${report.overallStatus}`);
    log.success(`Found ${report.prioritizedFindings.length} security issues`);

    // Phase 5: Output
    log.phase('Output Generation');
    const jsonOutput = outputJson(graph, analysis, report);
    const mermaidOutput = outputMermaid(graph, analysis);
    const htmlOutput = outputHtml(graph, analysis, report);

    const findingsReport = generateFindingReport(graph, analysis);
    const markdownReport = exportFindingsMarkdown(findingsReport);

    const outputDir = path.join(process.cwd(), 'web-wreck-output');
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').split('T')[0];
    const fileid = Math.random().toString(36).substring(2, 8);

    const htmlPath = path.join(outputDir, `report-${timestamp}-${fileid}.html`);
    const mdPath = path.join(outputDir, `report-${timestamp}-${fileid}.md`);

    fs.writeFileSync(htmlPath, htmlOutput, 'utf-8');
    fs.writeFileSync(mdPath, markdownReport, 'utf-8');

    console.log('\n=== JSON Output ===');
    console.log(JSON.stringify(jsonOutput, null, 2));

    console.log('\n=== Mermaid Diagram ===');
    console.log(mermaidOutput);

    console.log('\n=== HTML Report ===');
    console.log(`\nHTML report generated at: ${htmlPath}`);

    console.log('\n=== Markdown Report ===');
    console.log(`\nMarkdown report generated at: ${mdPath}`);

    log.success('Analysis complete');

  } catch (error) {
    log.error('Analysis failed', error);
    process.exit(1);
  }
}

main();