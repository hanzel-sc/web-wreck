/**
 * Analysis module exports
 * Phase 3: Auth presence analysis
 * Phase 4: Security findings
 */

export { analyzeAuthPresence } from './authPresence.js';
export type { AuthAnalysis, AuthBypass } from './authPresence.js';

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

export { generateSecurityReport } from './report.js';
export type { SecurityReport, RemediationItem } from './report.js';