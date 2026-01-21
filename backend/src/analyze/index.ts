/**
 * Analysis module exports
 * Phase 3: Auth presence analysis
 * Phase 4: Security findings
 */

export { analyzeAuthPresence } from './authPrescence.js';
export type { AuthAnalysis, AuthBypass } from './authPrescence.js';

export {
  generateFindingReport,
  exportFindingsMarkdown,
} from './findings.js';
export type {
  FindingReport,
  FindingSummary,
  RouteFinding,
  NodeFinding,
} from './findings.js';