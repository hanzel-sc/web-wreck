import type { ExecutionGraph } from '../ir/types.js';
import type { AuthAnalysis } from '../analyze/authPresence.js';
import type { SecurityReport } from '../analyze/index.js';
import { buildAdjacency, getOrderedExecutionChain } from '../util/graph.js';

/* ─────────────────────────────────────────────────────────────
 * Cytoscape.js element builder
 * Converts ExecutionGraph → flat { nodes[], edges[] } arrays
 * ────────────────────────────────────────────────────────── */

interface CyNode {
  data: {
    id: string;
    label: string;
    type: string;
    vulnerable?: boolean;
    safe?: boolean;
    isPublic?: boolean;
    file?: string;
    parent?: string;
  };
}
interface CyEdge {
  data: { id: string; source: string; target: string };
}

function buildCytoscapeElements(
  graph: ExecutionGraph,
  analysis: AuthAnalysis
): { nodes: CyNode[]; edges: CyEdge[] } {
  const nodes: CyNode[] = [];
  const edges: CyEdge[] = [];
  const addedNodes = new Set<string>();

  // Root node
  nodes.push({
    data: { id: 'root', label: 'App Entry', type: 'root' },
  });
  addedNodes.add('root');

  const adjacency = buildAdjacency(graph);

  for (const route of graph.routes) {
    const isInUnauthList = analysis.unauthenticated.includes(route.id);
    const routeFindings = analysis.allFindings.get(route.id) ?? [];
    const hasSecurityIssue = routeFindings.some(
      (f) => f.severity === 'critical' || f.severity === 'high' || f.severity === 'medium'
    );
    const isPublicEndpoint = routeFindings.some(
      (f) => f.type === 'public-endpoint' && f.severity === 'info'
    );
    const chain = getOrderedExecutionChain(graph, adjacency, route.entryNodeId);
    const routeHasAuth = chain.some((n) => n.type === 'auth');

    const isVulnerable = hasSecurityIssue;
    const isPublic = isPublicEndpoint && !hasSecurityIssue;
    const isProtected = routeHasAuth && !isVulnerable;

    // Route node
    const routeNodeId = route.id;
    if (!addedNodes.has(routeNodeId)) {
      nodes.push({
        data: {
          id: routeNodeId,
          label: `${route.method} ${route.path}`,
          type: 'route',
          vulnerable: isVulnerable,
          safe: isProtected,
          isPublic,
          file: route.sourceLocation.filePath,
        },
      });
      addedNodes.add(routeNodeId);
    }

    // Root → route edge
    edges.push({
      data: { id: `root->${routeNodeId}`, source: 'root', target: routeNodeId },
    });

    // Chain nodes + edges (limit to first 5 for readability)
    const chainSlice = chain.slice(0, 5);
    let prevId = routeNodeId;
    for (const node of chainSlice) {
      const nodeId = `${node.id}__${route.id}`;
      if (!addedNodes.has(nodeId)) {
        nodes.push({
          data: {
            id: nodeId,
            label: node.name,
            type: node.type,
            file: node.metadata.sourceLocation.filePath,
          },
        });
        addedNodes.add(nodeId);
      }
      const edgeId = `${prevId}->${nodeId}`;
      edges.push({ data: { id: edgeId, source: prevId, target: nodeId } });
      prevId = nodeId;
    }
  }

  return { nodes, edges };
}

/* ─────────────────────────────────────────────────────────────
 * Route detail data builder (for the slide-out panel)
 * ────────────────────────────────────────────────────────── */

interface RouteDetail {
  id: string;
  method: string;
  path: string;
  file: string;
  line: number;
  hasAuth: boolean;
  findings: { severity: string; message: string; remediation: string; cwe: string; type: string }[];
  chain: { name: string; type: string }[];
}

function buildRouteDetails(
  graph: ExecutionGraph,
  analysis: AuthAnalysis
): Record<string, RouteDetail> {
  const details: Record<string, RouteDetail> = {};
  const adjacency = buildAdjacency(graph);

  for (const route of graph.routes) {
    const findings = analysis.allFindings.get(route.id) ?? [];
    const chain = getOrderedExecutionChain(graph, adjacency, route.entryNodeId);
    details[route.id] = {
      id: route.id,
      method: route.method,
      path: route.path,
      file: route.sourceLocation.filePath.split(/[\\/]/).slice(-2).join('/'),
      line: route.sourceLocation.line,
      hasAuth: !analysis.unauthenticated.includes(route.id),
      findings: findings.map((f) => ({
        severity: f.severity,
        message: f.message,
        remediation: f.remediation ?? '',
        cwe: f.cwe ?? '',
        type: f.type,
      })),
      chain: chain.map((n) => ({ name: n.name, type: n.type })),
    };
  }
  return details;
}

/* ─────────────────────────────────────────────────────────────
 * Parse a repo URL into display-friendly parts
 * ────────────────────────────────────────────────────────── */

function parseRepoUrl(url: string): { host: string; owner: string; repo: string; display: string } {
  try {
    const u = new URL(url);
    const parts = u.pathname.replace(/\.git$/, '').split('/').filter(Boolean);
    return {
      host: u.hostname,
      owner: parts[0] ?? '',
      repo: parts[1] ?? parts[0] ?? url,
      display: parts.length >= 2 ? `${parts[0]}/${parts[1]}` : url,
    };
  } catch {
    return { host: '', owner: '', repo: url, display: url };
  }
}

/* ─────────────────────────────────────────────────────────────
 * Main HTML generator
 * ────────────────────────────────────────────────────────── */

export function outputHtml(
  graph: ExecutionGraph,
  analysis: AuthAnalysis,
  report: SecurityReport,
  repoUrl?: string
): string {
  const cyElements = buildCytoscapeElements(graph, analysis);
  const routeDetails = buildRouteDetails(graph, analysis);
  const now = new Date().toLocaleString('en-US', {
    month: 'short',
    day: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });

  const repo = parseRepoUrl(repoUrl ?? '');
  const repoDisplay = repoUrl ? repo.display : 'Local Analysis';
  const repoName = repoUrl ? repo.repo : 'Express App';

  const findingsJson = report.prioritizedFindings.map((f) => ({
    severity: f.severity,
    message: f.message,
    remediation: f.remediation ?? 'Review and apply security best practices.',
    cwe: f.cwe ?? '',
    type: f.type,
    category: f.category,
  }));

  const scoreColor =
    report.summary.riskScore > 70 ? '#ef4444' : report.summary.riskScore > 40 ? '#f97316' : '#22c55e';

  const methodColors: Record<string, string> = {
    GET: '#3b82f6',
    POST: '#22c55e',
    PUT: '#f97316',
    PATCH: '#f97316',
    DELETE: '#ef4444',
    USE: '#a855f7',
  };

  return `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Web-Wreck — Security Report</title>
  <meta name="description" content="Web-Wreck static security analysis report for Express.js application routes and middleware.">

  <!-- Cytoscape.js + Dagre layout -->
  <script src="https://unpkg.com/cytoscape@3.30.4/dist/cytoscape.min.js"></script>
  <script src="https://unpkg.com/dagre@0.8.5/dist/dagre.min.js"></script>
  <script src="https://unpkg.com/cytoscape-dagre@2.5.0/cytoscape-dagre.js"></script>

  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">

  <style>
    *, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }

    :root {
      --bg: #f8fafc; --surface: #ffffff; --surface2: #f1f5f9;
      --border: #e2e8f0; --border-strong: #cbd5e1;
      --text: #0f172a; --text-muted: #64748b; --text-faint: #94a3b8;
      --sidebar-bg: #0f172a; --sidebar-text: #94a3b8;
      --sidebar-active: #f8fafc; --sidebar-active-bg: #1e293b; --sidebar-hover: #1e293b;
      --accent: #6366f1; --accent-hover: #4f46e5;
      --critical: #ef4444; --critical-bg: #fef2f2; --critical-border: #fecaca;
      --high: #f97316; --high-bg: #fff7ed;
      --medium: #eab308; --medium-bg: #fefce8;
      --low: #22c55e; --low-bg: #f0fdf4;
      --info: #3b82f6; --info-bg: #eff6ff;
    }

    [data-theme="dark"] {
      --bg: #0a0f1e; --surface: #111827; --surface2: #1f2937;
      --border: #1f2937; --border-strong: #374151;
      --text: #f9fafb; --text-muted: #9ca3af; --text-faint: #6b7280;
      --sidebar-bg: #060b18; --sidebar-text: #6b7280;
      --sidebar-active: #f9fafb; --sidebar-active-bg: #111827; --sidebar-hover: #111827;
      --critical-bg: #1c1017; --critical-border: #7f1d1d;
      --high-bg: #1a1408; --medium-bg: #1a1a08;
      --low-bg: #0a1a0f; --info-bg: #0c1425;
    }

    body {
      font-family: 'Inter', system-ui, sans-serif;
      background: var(--bg); color: var(--text);
      display: flex; height: 100vh; overflow: hidden;
      font-size: 14px; line-height: 1.5;
    }

    /* ─── Sidebar ─────────────────────────────────────── */
    .sidebar {
      width: 220px; flex-shrink: 0; background: var(--sidebar-bg);
      display: flex; flex-direction: column; height: 100vh;
      position: relative; z-index: 20;
    }
    .sidebar-logo { padding: 20px 18px 16px; border-bottom: 1px solid rgba(255,255,255,0.06); }
    .sidebar-logo-mark { display: flex; align-items: center; gap: 8px; margin-bottom: 2px; }
    .logo-icon {
      width: 28px; height: 28px;
      background: linear-gradient(135deg, #6366f1, #8b5cf6);
      border-radius: 6px; display: flex; align-items: center; justify-content: center;
      color: white; font-weight: 800; font-size: 12px;
    }
    .logo-name { font-weight: 700; font-size: 15px; color: #f1f5f9; letter-spacing: -0.3px; }
    .logo-sub { font-size: 11px; color: var(--sidebar-text); margin-left: 36px; }

    .sidebar-nav {
      flex: 1; padding: 12px 10px; display: flex;
      flex-direction: column; gap: 2px; overflow-y: auto;
    }
    .nav-item {
      display: flex; align-items: center; gap: 10px;
      padding: 8px 10px; border-radius: 8px; cursor: pointer;
      color: var(--sidebar-text); font-size: 13.5px; font-weight: 500;
      transition: all 0.15s ease; border: none; background: none;
      width: 100%; text-align: left;
    }
    .nav-item:hover { background: var(--sidebar-hover); color: #e2e8f0; }
    .nav-item.active { background: var(--sidebar-active-bg); color: var(--sidebar-active); }
    .nav-item.active .nav-icon { color: #6366f1; }
    .nav-icon { width: 18px; height: 18px; opacity: 0.7; flex-shrink: 0; display: flex; align-items: center; justify-content: center; }
    .nav-item.active .nav-icon { opacity: 1; }
    .nav-badge {
      margin-left: auto; background: #ef4444; color: white;
      font-size: 10px; font-weight: 700; padding: 1px 6px;
      border-radius: 10px; min-width: 18px; text-align: center;
    }

    .sidebar-footer { padding: 16px 16px 20px; border-top: 1px solid rgba(255,255,255,0.06); }
    .repo-info { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
    .repo-avatar {
      width: 26px; height: 26px; border-radius: 50%;
      background: linear-gradient(135deg, #374151, #1f2937);
      display: flex; align-items: center; justify-content: center; flex-shrink: 0;
    }
    .repo-name { font-size: 12px; font-weight: 600; color: #e2e8f0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .repo-meta { font-size: 11px; color: var(--sidebar-text); margin-bottom: 2px; }
    .sidebar-quote {
      font-size: 10.5px; color: #374151; font-style: italic; line-height: 1.4;
      border-top: 1px solid rgba(255,255,255,0.04); padding-top: 10px; margin-top: 6px;
    }

    /* ─── Main Layout ─────────────────────────────────── */
    .main { flex: 1; display: flex; flex-direction: column; height: 100vh; overflow: hidden; }

    /* ─── Top Bar ─────────────────────────────────────── */
    .topbar {
      height: 56px; background: var(--surface); border-bottom: 1px solid var(--border);
      display: flex; align-items: center; padding: 0 20px; gap: 12px; flex-shrink: 0;
    }
    .search-box {
      flex: 1; max-width: 360px; display: flex; align-items: center; gap: 8px;
      background: var(--surface2); border: 1px solid var(--border); border-radius: 8px;
      padding: 0 12px; height: 34px; font-size: 13px; color: var(--text-muted); transition: border-color 0.15s;
    }
    .search-box:focus-within { border-color: var(--accent); }
    .search-box input {
      background: none; border: none; outline: none; flex: 1;
      font-size: 13px; color: var(--text); font-family: inherit;
    }
    .search-box input::placeholder { color: var(--text-muted); }
    .search-kbd { font-size: 10px; color: var(--text-faint); background: var(--border); padding: 1px 5px; border-radius: 4px; font-family: 'JetBrains Mono', monospace; }
    .topbar-spacer { flex: 1; }
    .topbar-btn {
      display: flex; align-items: center; gap: 6px; padding: 6px 12px;
      border-radius: 8px; border: 1px solid var(--border); background: var(--surface);
      color: var(--text); font-size: 13px; font-weight: 500; cursor: pointer;
      transition: all 0.15s; font-family: inherit;
    }
    .topbar-btn:hover { background: var(--surface2); border-color: var(--border-strong); }
    .topbar-btn.primary { background: var(--text); color: var(--surface); border-color: var(--text); }
    .topbar-btn.primary:hover { opacity: 0.85; }
    .theme-btn { width: 34px; height: 34px; padding: 0; border-radius: 8px; display: flex; align-items: center; justify-content: center; }

    /* ─── Panels ──────────────────────────────────────── */
    .content-area { flex: 1; overflow-y: auto; position: relative; }
    .panel { display: none; height: 100%; overflow-y: auto; }
    .panel.active { display: flex; flex-direction: column; }

    /* ─── Security Posture Row ────────────────────────── */
    .posture-section {
      padding: 20px 28px; display: flex; align-items: center; gap: 0;
      border-bottom: 1px solid var(--border); flex-shrink: 0;
    }
    .posture-block { padding-right: 32px; border-right: 1px solid var(--border); margin-right: 32px; }
    .posture-label { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); margin-bottom: 6px; }
    .posture-score { display: flex; align-items: baseline; gap: 6px; }
    .score-num { font-size: 40px; font-weight: 800; letter-spacing: -2px; line-height: 1; }
    .score-denom { font-size: 18px; font-weight: 500; color: var(--text-muted); }
    .score-status { margin-top: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; }
    .stats-row { display: flex; gap: 0; flex: 1; }
    .stat-cell { flex: 1; display: flex; flex-direction: column; padding: 0 20px; border-right: 1px solid var(--border); }
    .stat-cell:last-child { border-right: none; }
    .stat-num { font-size: 26px; font-weight: 700; letter-spacing: -0.5px; line-height: 1.2; }
    .stat-label { font-size: 12px; color: var(--text-muted); margin-top: 2px; }

    /* ─── Graph Area ──────────────────────────────────── */
    .graph-section {
      padding: 20px 28px; display: flex; gap: 16px;
      flex: 1; min-height: 400px;
    }
    .graph-card {
      flex: 1; background: var(--surface); border: 1px solid var(--border);
      border-radius: 12px; display: flex; flex-direction: column; overflow: hidden; min-height: 350px;
    }
    .graph-card-header {
      padding: 14px 20px 10px; border-bottom: 1px solid var(--border);
      display: flex; align-items: center; justify-content: space-between; flex-shrink: 0;
    }
    .graph-card-title { font-size: 15px; font-weight: 600; }
    .graph-card-sub { font-size: 12px; color: var(--text-muted); margin-top: 2px; }
    .graph-legend { display: flex; align-items: center; gap: 14px; }
    .legend-pip { display: flex; align-items: center; gap: 5px; font-size: 12px; color: var(--text-muted); }
    .pip-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
    .graph-controls { display: flex; align-items: center; gap: 6px; }
    .graph-btn {
      height: 28px; padding: 0 10px; border-radius: 6px;
      border: 1px solid var(--border); background: var(--surface); cursor: pointer;
      display: flex; align-items: center; justify-content: center;
      color: var(--text-muted); transition: all 0.15s; font-size: 11px; font-family: inherit;
    }
    .graph-btn:hover { background: var(--surface2); color: var(--text); }
    .graph-btn.active { background: var(--accent); color: white; border-color: var(--accent); }

    #cy-container { flex: 1; width: 100%; min-height: 300px; }

    /* ─── Detail Panel ────────────────────────────────── */
    .detail-panel {
      width: 320px; flex-shrink: 0; background: var(--surface);
      border: 1px solid var(--border); border-radius: 12px;
      display: flex; flex-direction: column; overflow: hidden;
    }
    .detail-panel.empty { align-items: center; justify-content: center; }
    .detail-empty-state { text-align: center; color: var(--text-faint); padding: 32px; }
    .detail-empty-state svg { margin-bottom: 12px; opacity: 0.4; }
    .detail-empty-state p { font-size: 13px; }

    .detail-header { padding: 16px 16px 12px; border-bottom: 1px solid var(--border); flex-shrink: 0; }
    .detail-route-name { font-family: 'JetBrains Mono', monospace; font-size: 14px; font-weight: 600; word-break: break-all; }
    .detail-route-file { font-size: 11px; color: var(--text-muted); margin-top: 3px; font-family: 'JetBrains Mono', monospace; }

    .detail-severity-badge {
      display: inline-flex; align-items: center; padding: 2px 8px;
      border-radius: 4px; font-size: 10px; font-weight: 700;
      text-transform: uppercase; letter-spacing: 0.5px; margin-top: 8px;
    }
    .badge-critical { background: var(--critical-bg); color: var(--critical); border: 1px solid var(--critical-border); }
    .badge-high { background: var(--high-bg); color: var(--high); }
    .badge-medium { background: var(--medium-bg); color: var(--medium); }
    .badge-low { background: var(--low-bg); color: var(--low); }
    .badge-info { background: var(--info-bg); color: var(--info); }
    .badge-safe { background: var(--low-bg); color: #16a34a; border: 1px solid #bbf7d0; }

    .detail-tabs { display: flex; border-bottom: 1px solid var(--border); padding: 0 12px; flex-shrink: 0; }
    .detail-tab {
      padding: 10px 10px; font-size: 12px; font-weight: 500;
      color: var(--text-muted); cursor: pointer;
      border-bottom: 2px solid transparent; margin-bottom: -1px;
      transition: all 0.15s; background: none; border-top: none;
      border-left: none; border-right: none; font-family: inherit;
    }
    .detail-tab.active { color: var(--accent); border-bottom-color: var(--accent); }
    .detail-tab:hover { color: var(--text); }
    .detail-body { flex: 1; overflow-y: auto; padding: 16px; }
    .detail-section { margin-bottom: 18px; }
    .detail-section-label { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); margin-bottom: 8px; }

    .auth-row { display: flex; align-items: center; justify-content: space-between; padding: 7px 0; border-bottom: 1px solid var(--border); }
    .auth-row:last-child { border-bottom: none; }
    .auth-row-label { font-size: 13px; font-weight: 500; }
    .status-ok { display: flex; align-items: center; gap: 4px; color: #16a34a; font-size: 12px; font-weight: 600; }
    .status-fail { display: flex; align-items: center; gap: 4px; color: var(--critical); font-size: 12px; font-weight: 600; }

    .chain-item { display: flex; align-items: center; gap: 10px; padding: 7px 0; border-bottom: 1px solid var(--border); }
    .chain-item:last-child { border-bottom: none; }
    .chain-num {
      width: 20px; height: 20px; border-radius: 50%;
      background: var(--surface2); border: 1px solid var(--border);
      font-size: 10px; font-weight: 700; display: flex; align-items: center;
      justify-content: center; color: var(--text-muted); flex-shrink: 0;
    }
    .chain-name { font-family: 'JetBrains Mono', monospace; font-size: 12px; flex: 1; }
    .chain-type { font-size: 10px; color: var(--text-faint); text-transform: capitalize; }
    .chain-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }

    .finding-card {
      background: var(--critical-bg); border: 1px solid var(--critical-border);
      border-radius: 8px; padding: 12px; margin-bottom: 10px;
    }
    .finding-msg { font-size: 12.5px; font-weight: 500; line-height: 1.4; margin-bottom: 6px; }
    .finding-remedy { font-size: 12px; color: var(--text-muted); line-height: 1.4; }
    .finding-cwe { font-size: 10px; font-family: 'JetBrains Mono', monospace; color: var(--text-faint); margin-top: 6px; }

    /* ─── Findings Table ──────────────────────────────── */
    .findings-section { padding: 0 28px 28px; flex-shrink: 0; }
    .findings-header { display: flex; align-items: center; justify-content: space-between; padding: 20px 0 14px; }
    .findings-title { font-size: 17px; font-weight: 600; }
    .findings-sub { font-size: 12px; color: var(--text-muted); margin-top: 2px; }
    .findings-filters { display: flex; align-items: center; gap: 8px; }

    .filter-select {
      height: 32px; padding: 0 10px; border: 1px solid var(--border);
      border-radius: 6px; background: var(--surface); color: var(--text);
      font-size: 12.5px; font-family: inherit; cursor: pointer; outline: none;
    }
    .filter-search {
      height: 32px; padding: 0 10px; border: 1px solid var(--border);
      border-radius: 6px; background: var(--surface); color: var(--text);
      font-size: 12.5px; font-family: inherit; outline: none; width: 180px;
    }
    .filter-search::placeholder { color: var(--text-faint); }

    .findings-table {
      width: 100%; border-collapse: collapse; background: var(--surface);
      border: 1px solid var(--border); border-radius: 10px; overflow: hidden;
    }
    .findings-table th {
      background: var(--surface2); text-align: left; padding: 10px 16px;
      font-size: 11.5px; font-weight: 600; color: var(--text-muted);
      text-transform: uppercase; letter-spacing: 0.4px; border-bottom: 1px solid var(--border);
    }
    .findings-table td {
      padding: 12px 16px; border-bottom: 1px solid var(--border);
      vertical-align: top; font-size: 13px;
    }
    .findings-table tr:last-child td { border-bottom: none; }
    .findings-table tr:hover td { background: var(--surface2); }

    .sev-badge {
      display: inline-flex; align-items: center; padding: 3px 8px;
      border-radius: 5px; font-size: 10.5px; font-weight: 700;
      text-transform: uppercase; letter-spacing: 0.5px; white-space: nowrap;
    }
    .sev-critical { background: var(--critical-bg); color: var(--critical); border: 1px solid var(--critical-border); }
    .sev-high { background: var(--high-bg); color: var(--high); }
    .sev-medium { background: var(--medium-bg); color: var(--medium); }
    .sev-low { background: var(--low-bg); color: var(--low); }
    .sev-info { background: var(--info-bg); color: var(--info); }

    .empty-findings { text-align: center; padding: 40px; color: var(--text-faint); }

    /* ─── Report Header ───────────────────────────────── */
    .report-header { padding: 28px 28px 0; flex-shrink: 0; }
    .report-title-row { display: flex; align-items: flex-start; justify-content: space-between; gap: 20px; flex-wrap: wrap; }
    .report-title { font-size: 26px; font-weight: 700; letter-spacing: -0.5px; }
    .report-subtitle { color: var(--text-muted); margin-top: 3px; font-size: 14px; }
    .report-meta { display: flex; gap: 24px; flex-shrink: 0; }
    .meta-item { display: flex; flex-direction: column; align-items: flex-end; }
    .meta-label { font-size: 11px; color: var(--text-faint); text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; }
    .meta-value { font-size: 13px; font-weight: 600; color: var(--text); margin-top: 1px; }

    /* ─── Scrollbars ──────────────────────────────────── */
    ::-webkit-scrollbar { width: 5px; height: 5px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: var(--border-strong); border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: var(--text-faint); }

    @media (max-width: 900px) {
      .sidebar { display: none; }
      .graph-section { flex-direction: column; }
      .detail-panel { width: 100%; }
    }
  </style>
</head>
<body>

  <!-- ─── Sidebar ──────────────────────────────────────── -->
  <aside class="sidebar">
    <div class="sidebar-logo">
      <div class="sidebar-logo-mark">
        <div class="logo-icon">//</div>
        <span class="logo-name">Web-Wreck</span>
      </div>
      <div class="logo-sub">Static Security Analysis</div>
    </div>

    <nav class="sidebar-nav">
      <button class="nav-item active" id="nav-report" onclick="showPanel('report')">
        <span class="nav-icon"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg></span>
        Report
      </button>
      <button class="nav-item" id="nav-findings" onclick="showPanel('findings')">
        <span class="nav-icon"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg></span>
        Findings
        ${report.summary.totalFindings > 0 ? `<span class="nav-badge">${report.summary.totalFindings}</span>` : ''}
      </button>
      <button class="nav-item" id="nav-graph" onclick="showPanel('graph')">
        <span class="nav-icon"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="2"/><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4"/></svg></span>
        Graph
      </button>
      <button class="nav-item" id="nav-routes" onclick="showPanel('routes')">
        <span class="nav-icon"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg></span>
        Routes
      </button>
    </nav>

    <div class="sidebar-footer">
      <div class="repo-info">
        <div class="repo-avatar"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#9ca3af" stroke-width="2"><path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 00-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0020 4.77 5.07 5.07 0 0019.91 1S18.73.65 16 2.48a13.38 13.38 0 00-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 005 4.77a5.44 5.44 0 00-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 009 18.13V22"/></svg></div>
        <div><div class="repo-name">${repoDisplay}</div></div>
      </div>
      <div class="repo-meta">Node.js / Express</div>
      <div class="repo-meta">Analyzed ${now}</div>
      ${repoUrl ? `<div class="repo-meta" style="margin-top:4px;"><a href="${repoUrl}" target="_blank" rel="noopener" style="color:#6366f1;text-decoration:none;font-size:11px;">Open Repository ↗</a></div>` : ''}
      <div class="sidebar-quote">"Safer code<br>builds bolder ideas."</div>
    </div>
  </aside>

  <!-- ─── Main ─────────────────────────────────────────── -->
  <div class="main">

    <!-- Top Bar -->
    <div class="topbar">
      <div class="search-box">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        <input type="text" placeholder="Search routes, middleware, findings..." id="global-search" oninput="onGlobalSearch(this.value)">
        <span class="search-kbd">Ctrl K</span>
      </div>
      <div class="topbar-spacer"></div>
      <button class="topbar-btn theme-btn" onclick="toggleTheme()" title="Toggle theme">
        <svg id="moon-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:none"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
        <svg id="sun-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
      </button>
      <button class="topbar-btn" onclick="exportReport()">Export</button>
      <button class="topbar-btn primary" onclick="showPanel('graph')">View Graph</button>
    </div>

    <!-- Content Area -->
    <div class="content-area">

      <!-- ─── REPORT PANEL ──────────────────────────── -->
      <div class="panel active" id="panel-report">

        <div class="report-header">
          <div class="report-title-row">
            <div>
              <h1 class="report-title">Security Report</h1>
              <p class="report-subtitle">Source code based semantic analysis &bull; ${repoDisplay}</p>
            </div>
            <div class="report-meta">
              <div class="meta-item">
                <span class="meta-label">Repository</span>
                <span class="meta-value">${repoName}</span>
              </div>
              <div class="meta-item">
                <span class="meta-label">Framework</span>
                <span class="meta-value">Express</span>
              </div>
              <div class="meta-item">
                <span class="meta-label">Analyzed</span>
                <span class="meta-value">${now}</span>
              </div>
            </div>
          </div>
        </div>

        <div class="posture-section">
          <div class="posture-block">
            <div class="posture-label">Security Posture</div>
            <div class="posture-score">
              <span class="score-num" style="color: ${scoreColor}">${report.summary.riskScore}</span>
              <span class="score-denom">/ 100</span>
            </div>
            <div class="score-status" style="color: ${scoreColor}">${report.overallStatus.toUpperCase()} RISK</div>
          </div>
          <div class="stats-row">
            <div class="stat-cell"><span class="stat-num" style="color:var(--critical)">${report.summary.criticalIssues}</span><span class="stat-label">Critical</span></div>
            <div class="stat-cell"><span class="stat-num" style="color:var(--high)">${report.summary.highIssues}</span><span class="stat-label">High</span></div>
            <div class="stat-cell"><span class="stat-num">${report.summary.totalFindings}</span><span class="stat-label">Findings</span></div>
            <div class="stat-cell"><span class="stat-num">${graph.routes.length}</span><span class="stat-label">Routes</span></div>
            <div class="stat-cell"><span class="stat-num">${graph.nodes.size}</span><span class="stat-label">Nodes</span></div>
            <div class="stat-cell"><span class="stat-num">${analysis.authNodes.length}</span><span class="stat-label">Auth</span></div>
          </div>
        </div>

        <!-- Graph area in Report panel -->
        <div class="graph-section">
          <div class="graph-card" style="flex:1.3;">
            <div class="graph-card-header">
              <div>
                <div class="graph-card-title">Execution Graph</div>
                <div class="graph-card-sub">Authentication &amp; authorization flow</div>
              </div>
              <div style="display:flex;align-items:center;gap:16px;">
                <div class="graph-legend">
                  <div class="legend-pip"><div class="pip-dot" style="background:#3b82f6"></div>Route</div>
                  <div class="legend-pip"><div class="pip-dot" style="background:#a855f7"></div>Auth</div>
                  <div class="legend-pip"><div class="pip-dot" style="background:#64748b"></div>Handler</div>
                  <div class="legend-pip"><div class="pip-dot" style="background:#ef4444"></div>Vulnerable</div>
                  <div class="legend-pip"><div class="pip-dot" style="background:#22c55e"></div>Protected</div>
                </div>
                <div class="graph-controls">
                  <button class="graph-btn active" id="btn-dagre" onclick="setLayout('dagre')">Tree</button>
                  <button class="graph-btn" id="btn-cose" onclick="setLayout('cose')">Force</button>
                  <button class="graph-btn" onclick="cyFit()">Fit</button>
                  <button class="graph-btn" onclick="cyReset()">Reset</button>
                </div>
              </div>
            </div>
            <div id="cy-container"></div>
          </div>

          <!-- Detail panel -->
          <div class="detail-panel empty" id="detail-panel">
            <div class="detail-empty-state">
              <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="2"/><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4"/></svg>
              <p>Click a route node<br>to inspect details</p>
            </div>
          </div>
        </div>

        <!-- Findings table -->
        <div class="findings-section">
          <div class="findings-header">
            <div><div class="findings-title">Findings</div><div class="findings-sub">Detected security issues sorted by severity</div></div>
            <div class="findings-filters">
              <select class="filter-select" id="sev-filter" onchange="filterFindings()">
                <option value="">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
              <input type="text" class="filter-search" placeholder="Filter findings..." id="finding-search" oninput="filterFindings()">
            </div>
          </div>
          <table class="findings-table" id="findings-table">
            <thead><tr><th>Severity</th><th>Route / Type</th><th>Issue</th><th>Recommendation</th></tr></thead>
            <tbody id="findings-tbody">
              ${findingsJson.length === 0
                ? `<tr><td colspan="4" class="empty-findings">No security findings detected.</td></tr>`
                : findingsJson.map((f) => `
              <tr class="finding-row" data-severity="${f.severity}" data-type="${f.type}" data-msg="${f.message.toLowerCase()}">
                <td><span class="sev-badge sev-${f.severity}">${f.severity}</span></td>
                <td><div style="font-weight:600;font-size:13px;">${f.type.split('-').map((w: string) => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')}</div><div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-muted);margin-top:2px;">${f.category}</div></td>
                <td style="max-width:280px;">${f.message}</td>
                <td style="max-width:240px;color:var(--text-muted)">${f.remediation}</td>
              </tr>`).join('')}
            </tbody>
          </table>
          <div style="padding:12px 0;color:var(--text-faint);font-size:12px;" id="findings-count">Showing ${findingsJson.length} of ${findingsJson.length} findings</div>
        </div>
      </div>

      <!-- ─── FINDINGS PANEL ─────────────────────────── -->
      <div class="panel" id="panel-findings">
        <div style="padding:28px;">
          <h2 style="font-size:22px;font-weight:700;margin-bottom:4px;">All Findings</h2>
          <p style="color:var(--text-muted);margin-bottom:20px;font-size:14px;">Complete list of detected security issues across all routes</p>
          ${report.prioritizedFindings.length === 0
            ? `<div class="empty-findings" style="padding:60px;"><p style="font-size:16px;font-weight:600;">No Findings</p><p>All routes appear to be properly secured.</p></div>`
            : `<table class="findings-table"><thead><tr><th>Severity</th><th>Type</th><th>Issue</th><th>CWE</th><th>Remediation</th></tr></thead><tbody>
              ${report.prioritizedFindings.map((f) => `<tr>
                <td><span class="sev-badge sev-${f.severity}">${f.severity}</span></td>
                <td style="font-family:'JetBrains Mono',monospace;font-size:11px;">${f.type}</td>
                <td>${f.message}</td>
                <td style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-muted)">${f.cwe ?? '—'}</td>
                <td style="color:var(--text-muted)">${f.remediation ?? '—'}</td>
              </tr>`).join('')}
            </tbody></table>`
          }
        </div>
      </div>

      <!-- ─── GRAPH PANEL (Full page) ────────────────── -->
      <div class="panel" id="panel-graph">
        <div style="padding:20px 28px 0;flex-shrink:0;">
          <h2 style="font-size:20px;font-weight:700;">Execution Graph</h2>
          <p style="color:var(--text-muted);font-size:13px;margin-top:2px;">Full authentication and authorization flow across all routes &bull; ${repoDisplay}</p>
        </div>
        <div style="flex:1;padding:16px 28px 28px;min-height:0;display:flex;">
          <div class="graph-card" style="flex:1;">
            <div class="graph-card-header">
              <div class="graph-legend">
                <div class="legend-pip"><div class="pip-dot" style="background:#3b82f6"></div>Route</div>
                <div class="legend-pip"><div class="pip-dot" style="background:#a855f7"></div>Auth</div>
                <div class="legend-pip"><div class="pip-dot" style="background:#64748b"></div>Handler</div>
                <div class="legend-pip"><div class="pip-dot" style="background:#ef4444"></div>Vulnerable</div>
                <div class="legend-pip"><div class="pip-dot" style="background:#22c55e"></div>Protected</div>
              </div>
              <div class="graph-controls">
                <button class="graph-btn active" id="btn-dagre-full" onclick="setLayout('dagre')">Tree</button>
                <button class="graph-btn" id="btn-cose-full" onclick="setLayout('cose')">Force</button>
                <button class="graph-btn" onclick="cyFit()">Fit</button>
                <button class="graph-btn" onclick="cyReset()">Reset</button>
              </div>
            </div>
            <div id="cy-container-full" style="flex:1;width:100%;min-height:400px;"></div>
          </div>
        </div>
      </div>

      <!-- ─── ROUTES PANEL ──────────────────────────── -->
      <div class="panel" id="panel-routes">
        <div style="padding:28px;">
          <h2 style="font-size:22px;font-weight:700;margin-bottom:4px;">Routes</h2>
          <p style="color:var(--text-muted);margin-bottom:12px;font-size:14px;">All analyzed route definitions</p>
          <input type="text" class="filter-search" placeholder="Search routes..." id="route-search" oninput="filterRoutes()" style="margin-bottom:16px;width:280px;">
          <table class="findings-table" id="routes-table">
            <thead><tr><th>Method</th><th>Path</th><th>Auth</th><th>Status</th><th>File</th></tr></thead>
            <tbody>
              ${graph.routes.map((route) => {
                const rf = analysis.allFindings.get(route.id) ?? [];
                const hasAuth = !analysis.unauthenticated.includes(route.id);
                const hasCritical = rf.some((f) => f.severity === 'critical' || f.severity === 'high');
                const isPublic = rf.some((f) => f.type === 'public-endpoint');
                const shortFile = route.sourceLocation.filePath.split(/[\\/]/).slice(-2).join('/');
                const mColor = methodColors[route.method.toUpperCase()] ?? '#64748b';
                return `<tr class="route-row" data-route="${route.id}" data-search="${route.method.toLowerCase()} ${route.path.toLowerCase()}" onclick="selectRoute('${route.id}')" style="cursor:pointer;">
                  <td><span style="font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:700;color:${mColor};background:${mColor}18;padding:2px 8px;border-radius:4px;">${route.method}</span></td>
                  <td style="font-family:'JetBrains Mono',monospace;font-size:12px;">${route.path}</td>
                  <td>${hasAuth ? '<span style="color:#22c55e;font-size:12px;font-weight:600;">✓</span>' : '<span style="color:#ef4444;font-size:12px;font-weight:600;">✗</span>'}</td>
                  <td>${hasCritical ? '<span class="sev-badge sev-critical">Vuln</span>' : isPublic ? '<span class="sev-badge sev-info">Public</span>' : hasAuth ? '<span class="sev-badge sev-low">OK</span>' : '<span class="sev-badge sev-medium">Review</span>'}</td>
                  <td style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-muted);">${shortFile}:${route.sourceLocation.line}</td>
                </tr>`;
              }).join('')}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  </div>

  <script>
    /* ── Data ─────────────────────────────────────────── */
    const cyElements = ${JSON.stringify({ nodes: cyElements.nodes, edges: cyElements.edges })};
    const routeDetails = ${JSON.stringify(routeDetails)};

    /* ── State ────────────────────────────────────────── */
    let cy = null;
    let currentLayoutName = 'dagre';

    /* ── Cytoscape Init ──────────────────────────────── */
    function initCy(containerId) {
      const container = document.getElementById(containerId);
      if (!container || container.clientHeight < 10) return null;

      return cytoscape({
        container: container,
        elements: {
          nodes: cyElements.nodes,
          edges: cyElements.edges,
        },
        style: [
          { selector: 'node', style: {
            'label': 'data(label)',
            'font-size': '9px',
            'font-family': "'JetBrains Mono', monospace",
            'text-valign': 'bottom',
            'text-halign': 'center',
            'text-margin-y': 6,
            'color': '#9ca3af',
            'width': 14,
            'height': 14,
            'border-width': 1.5,
            'text-max-width': '100px',
            'text-wrap': 'ellipsis',
          }},
          { selector: 'node[type="root"]', style: {
            'background-color': '#0f172a',
            'border-color': '#334155',
            'width': 24, 'height': 24,
            'color': '#94a3b8',
            'font-size': '10px',
            'font-weight': 700,
          }},
          { selector: 'node[type="route"]', style: {
            'background-color': '#3b82f6',
            'border-color': '#1d4ed8',
            'width': 16, 'height': 16,
            'font-size': '8px',
          }},
          { selector: 'node[type="auth"]', style: {
            'background-color': '#a855f7',
            'border-color': '#7c3aed',
            'shape': 'diamond',
            'width': 14, 'height': 14,
          }},
          { selector: 'node[type="middleware"]', style: {
            'background-color': '#64748b',
            'border-color': '#475569',
            'width': 12, 'height': 12,
          }},
          { selector: 'node[type="handler"]', style: {
            'background-color': '#64748b',
            'border-color': '#475569',
            'width': 12, 'height': 12,
          }},
          { selector: 'node[?vulnerable]', style: {
            'background-color': '#ef4444',
            'border-color': '#b91c1c',
            'border-width': 2.5,
          }},
          { selector: 'node[?safe]', style: {
            'background-color': '#22c55e',
            'border-color': '#15803d',
          }},
          { selector: 'node[?isPublic]', style: {
            'background-color': '#3b82f6',
            'border-color': '#1d4ed8',
          }},
          { selector: 'edge', style: {
            'width': 1.2,
            'line-color': '#374151',
            'target-arrow-color': '#374151',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'arrow-scale': 0.6,
            'opacity': 0.6,
          }},
          { selector: 'node:selected', style: {
            'border-width': 3,
            'border-color': '#6366f1',
            'overlay-opacity': 0,
          }},
          { selector: '.dimmed', style: {
            'opacity': 0.15,
          }},
          { selector: '.highlighted', style: {
            'opacity': 1,
            'border-width': 3,
            'border-color': '#facc15',
          }},
        ],
        layout: { name: 'preset' },
        minZoom: 0.05,
        maxZoom: 4,
        wheelSensitivity: 0.3,
      });
    }

    function runLayout(instance, name) {
      if (!instance) return;
      const opts = name === 'dagre'
        ? {
            name: 'dagre',
            rankDir: 'LR',
            nodeSep: 30,
            rankSep: 80,
            edgeSep: 10,
            animate: true,
            animationDuration: 400,
            fit: true,
            padding: 40,
          }
        : {
            name: 'cose',
            animate: true,
            animationDuration: 500,
            fit: true,
            padding: 40,
            nodeRepulsion: function(){ return 8000; },
            idealEdgeLength: function(){ return 80; },
            edgeElasticity: function(){ return 100; },
            gravity: 0.25,
          };
      instance.layout(opts).run();
    }

    /* ── Panel Navigation ────────────────────────────── */
    function showPanel(name) {
      document.querySelectorAll('.panel').forEach(p => { p.classList.remove('active'); p.style.display = 'none'; });
      document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));

      const panel = document.getElementById('panel-' + name);
      if (panel) { panel.classList.add('active'); panel.style.display = 'flex'; }
      const navBtn = document.getElementById('nav-' + name);
      if (navBtn) navBtn.classList.add('active');

      // Graph panel: need to init/resize Cytoscape in the right container
      if (name === 'graph') {
        setTimeout(() => {
          if (!cy) {
            cy = initCy('cy-container-full');
            if (cy) {
              runLayout(cy, currentLayoutName);
              attachCyEvents(cy);
            }
          } else {
            // Move cy to the full panel container
            const fullContainer = document.getElementById('cy-container-full');
            if (fullContainer && cy.container() !== fullContainer) {
              cy.mount(fullContainer);
            }
            cy.resize();
            cy.fit(undefined, 40);
          }
        }, 60);
      } else if (name === 'report') {
        setTimeout(() => {
          if (!cy) {
            cy = initCy('cy-container');
            if (cy) {
              runLayout(cy, currentLayoutName);
              attachCyEvents(cy);
            }
          } else {
            const reportContainer = document.getElementById('cy-container');
            if (reportContainer && cy.container() !== reportContainer) {
              cy.mount(reportContainer);
            }
            cy.resize();
            cy.fit(undefined, 40);
          }
        }, 60);
      }
    }

    /* ── Cytoscape Events ────────────────────────────── */
    function attachCyEvents(instance) {
      instance.on('tap', 'node[type="route"]', (e) => {
        const routeId = e.target.id();
        openRouteDetail(routeId);
      });
    }

    /* ── Layout Switch ───────────────────────────────── */
    function setLayout(name) {
      currentLayoutName = name;
      if (cy) runLayout(cy, name);

      // Update button active states
      document.querySelectorAll('.graph-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('[id^="btn-' + name + '"]').forEach(b => b.classList.add('active'));
      if (name === 'dagre') {
        document.querySelectorAll('[id^="btn-dagre"]').forEach(b => b.classList.add('active'));
      } else {
        document.querySelectorAll('[id^="btn-cose"]').forEach(b => b.classList.add('active'));
      }
    }

    function cyFit() { if (cy) cy.fit(undefined, 40); }
    function cyReset() { if (cy) { cy.reset(); cy.fit(undefined, 40); } }

    /* ── Theme ───────────────────────────────────────── */
    function toggleTheme() {
      const html = document.documentElement;
      const isDark = html.getAttribute('data-theme') === 'dark';
      html.setAttribute('data-theme', isDark ? 'light' : 'dark');
      document.getElementById('moon-icon').style.display = isDark ? '' : 'none';
      document.getElementById('sun-icon').style.display = isDark ? 'none' : '';

      // Update Cytoscape edge/text colors for theme
      if (cy) {
        const edgeColor = isDark ? '#cbd5e1' : '#374151';
        const textColor = isDark ? '#374151' : '#9ca3af';
        cy.style().selector('edge').style({ 'line-color': edgeColor, 'target-arrow-color': edgeColor }).update();
        cy.style().selector('node').style({ 'color': textColor }).update();
      }
    }

    /* ── Export ───────────────────────────────────────── */
    function exportReport() {
      const blob = new Blob([document.documentElement.outerHTML], { type: 'text/html' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'web-wreck-report.html';
      a.click();
    }

    /* ── Global Search ───────────────────────────────── */
    function onGlobalSearch(query) {
      const q = query.toLowerCase().trim();

      // 1. Filter findings table in report
      filterFindings(q);

      // 2. Filter routes table
      filterRoutes(q);

      // 3. Highlight matching nodes in graph
      if (cy) {
        if (!q) {
          cy.elements().removeClass('dimmed highlighted');
          return;
        }
        cy.elements().addClass('dimmed');
        const matchingNodes = cy.nodes().filter(n => {
          const label = (n.data('label') || '').toLowerCase();
          return label.includes(q);
        });
        matchingNodes.removeClass('dimmed').addClass('highlighted');
        // Also show connected edges and neighbors
        matchingNodes.connectedEdges().removeClass('dimmed');
        matchingNodes.neighborhood('node').removeClass('dimmed');
      }
    }

    /* ── Findings Filter ─────────────────────────────── */
    function filterFindings(searchOverride) {
      const sevFilter = (document.getElementById('sev-filter') || {}).value || '';
      const searchText = searchOverride !== undefined
        ? searchOverride
        : ((document.getElementById('finding-search') || {}).value || '').toLowerCase();

      const rows = document.querySelectorAll('.finding-row');
      let shown = 0;
      rows.forEach(row => {
        const sev = row.dataset.severity || '';
        const msg = row.dataset.msg || '';
        const type = row.dataset.type || '';
        const visible = (!sevFilter || sev === sevFilter) && (!searchText || msg.includes(searchText) || type.includes(searchText));
        row.style.display = visible ? '' : 'none';
        if (visible) shown++;
      });
      const countEl = document.getElementById('findings-count');
      if (countEl) countEl.textContent = 'Showing ' + shown + ' of ' + rows.length + ' findings';
    }

    /* ── Routes Filter ───────────────────────────────── */
    function filterRoutes(searchOverride) {
      const searchText = searchOverride !== undefined
        ? searchOverride
        : ((document.getElementById('route-search') || {}).value || '').toLowerCase();

      document.querySelectorAll('.route-row').forEach(row => {
        const data = row.dataset.search || '';
        row.style.display = (!searchText || data.includes(searchText)) ? '' : 'none';
      });
    }

    /* ── Route Selection from table ──────────────────── */
    function selectRoute(routeId) {
      showPanel('report');
      setTimeout(() => openRouteDetail(routeId), 100);
    }

    /* ── Detail Panel ────────────────────────────────── */
    function openRouteDetail(routeId) {
      const rd = routeDetails[routeId];
      if (!rd) return;

      // Highlight node in graph
      if (cy) {
        cy.elements().unselect();
        const node = cy.getElementById(routeId);
        if (node.length) node.select();
      }

      const panel = document.getElementById('detail-panel');
      panel.classList.remove('empty');

      const maxSev = rd.findings.length > 0
        ? (rd.findings.some(f => f.severity === 'critical') ? 'critical'
          : rd.findings.some(f => f.severity === 'high') ? 'high'
          : rd.findings.some(f => f.severity === 'medium') ? 'medium'
          : rd.findings.some(f => f.severity === 'low') ? 'low' : 'info')
        : (rd.hasAuth ? 'safe' : 'info');

      const methodColors = { GET:'#3b82f6',POST:'#22c55e',PUT:'#f97316',PATCH:'#f97316',DELETE:'#ef4444',USE:'#a855f7' };
      const mColor = methodColors[rd.method.toUpperCase()] || '#64748b';
      const typeColors = { auth:'#a855f7', handler:'#64748b', middleware:'#64748b', route:'#3b82f6', root:'#0f172a' };

      panel.innerHTML =
        '<div class="detail-header">' +
          '<div class="detail-route-name"><span style="color:' + mColor + ';margin-right:6px;">' + rd.method + '</span>' + rd.path + '</div>' +
          '<div class="detail-route-file">' + rd.file + ':' + rd.line + '</div>' +
          '<span class="detail-severity-badge badge-' + maxSev + '">' + (maxSev === 'safe' ? 'Protected' : maxSev.toUpperCase()) + '</span>' +
        '</div>' +
        '<div class="detail-tabs">' +
          '<button class="detail-tab active" onclick="switchTab(this,\\'overview\\')">Overview</button>' +
          '<button class="detail-tab" onclick="switchTab(this,\\'path\\')">Path</button>' +
          '<button class="detail-tab" onclick="switchTab(this,\\'source\\')">Source</button>' +
        '</div>' +
        '<div class="detail-body" id="dtab-overview">' +
          '<div class="detail-section"><div class="detail-section-label">Security Status</div>' +
            '<div class="auth-row"><span class="auth-row-label">Authentication</span>' +
              (rd.hasAuth ? '<span class="status-ok">✓ Present</span>' : '<span class="status-fail">✗ Missing</span>') +
            '</div>' +
            '<div class="auth-row"><span class="auth-row-label">Authorization</span>' +
              (rd.findings.some(f => f.type === 'missing-authorization' || f.type === 'missing-authentication')
                ? '<span class="status-fail">✗ Missing</span>'
                : '<span class="status-ok">✓ Present</span>') +
            '</div>' +
          '</div>' +
          (rd.findings.length > 0
            ? '<div class="detail-section"><div class="detail-section-label">Findings</div>' +
              rd.findings.map(f =>
                '<div class="finding-card"><div class="finding-msg">' + f.message + '</div>' +
                (f.remediation ? '<div class="finding-remedy">' + f.remediation + '</div>' : '') +
                (f.cwe ? '<div class="finding-cwe">' + f.cwe + '</div>' : '') +
                '</div>'
              ).join('') +
              '</div>'
            : '<div class="detail-section"><div style="color:var(--text-muted);font-size:12.5px;padding:8px 0;">No issues found.</div></div>'
          ) +
        '</div>' +
        '<div class="detail-body" id="dtab-path" style="display:none;">' +
          '<div class="detail-section"><div class="detail-section-label">Execution Path</div>' +
          rd.chain.slice(0, 14).map(function(n, i) {
            return '<div class="chain-item">' +
              '<div class="chain-num">' + (i+1) + '</div>' +
              '<div class="chain-dot" style="background:' + (typeColors[n.type]||'#64748b') + '"></div>' +
              '<span class="chain-name">' + n.name + '</span>' +
              '<span class="chain-type">' + n.type + '</span>' +
            '</div>';
          }).join('') +
          (rd.chain.length > 14 ? '<div style="color:var(--text-faint);font-size:11px;padding:8px 0;">+' + (rd.chain.length-14) + ' more…</div>' : '') +
          '</div>' +
        '</div>' +
        '<div class="detail-body" id="dtab-source" style="display:none;">' +
          '<div class="detail-section"><div class="detail-section-label">Source Location</div>' +
            '<div style="background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:12px;font-family:\\'JetBrains Mono\\',monospace;font-size:11.5px;line-height:1.6;">' +
              '<div style="color:var(--text-muted);">// ' + rd.file + '</div>' +
              '<div style="color:var(--text-faint);">Line ' + rd.line + '</div>' +
              '<div style="margin-top:8px;color:' + mColor + ';">' + rd.method.toLowerCase() + "('" + rd.path + "', ...)</div>" +
            '</div>' +
          '</div>' +
        '</div>';
    }

    function switchTab(btn, tabName) {
      document.querySelectorAll('.detail-tab').forEach(t => t.classList.remove('active'));
      btn.classList.add('active');
      ['overview','path','source'].forEach(t => {
        const el = document.getElementById('dtab-' + t);
        if (el) el.style.display = t === tabName ? 'block' : 'none';
      });
    }

    /* ── Keyboard Shortcut ───────────────────────────── */
    document.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        const input = document.getElementById('global-search');
        if (input) input.focus();
      }
    });

    /* ── Init ─────────────────────────────────────────── */
    window.addEventListener('DOMContentLoaded', () => {
      showPanel('report');
    });

    window.addEventListener('resize', () => {
      if (cy) cy.resize();
    });
  </script>
</body>
</html>`;
}