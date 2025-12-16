/**
 * Analysis orchestrator
 * Coordinates all analysis passes
 * 
 * Future passes might include:
 * - SQL injection detection
 * - XSS vulnerability detection
 * - CSRF protection analysis
 * - Rate limiting detection
 */

import { analyzeAuthPresence } from './authPrescence.js';

export { analyzeAuthPresence };