import type { ExecutionGraph, NodeKind } from '../ir/types.js';
import type { AuthAnalysis } from '../analyze/authPresence.js';
import type { SecurityReport } from '../analyze/index.js';

/**
 * Generate a complete HTML page with interactive D3.js visualization
 */
export function outputHtml(graph: ExecutionGraph, analysis: AuthAnalysis, report: SecurityReport): string {
  const treeData = generateTreeData(graph, analysis);
  const now = new Date().toLocaleString();

  // Use a simple string concatenation or be extremely careful with backticks
  // We'll use backticks but ensure proper escaping
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>West-Wreck Security Report - ${report.overallStatus}</title>
  <script src="https://d3js.org/d3.v7.min.js"></script>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      background: #f0f2f5;
      color: #1c1e21;
      line-height: 1.5;
    }
    
    .container { max-width: 1400px; margin: 0 auto; padding: 2rem; }
    
    .header {
      background: linear-gradient(135deg, #1a2a6c, #b21f1f, #fdbb2d);
      color: white;
      padding: 3rem 2rem;
      border-radius: 12px;
      margin-bottom: 2rem;
      box-shadow: 0 4px 20px rgba(0,0,0,0.15);
      text-align: center;
    }

    .status-badge {
      display: inline-block;
      padding: 0.5rem 1.5rem;
      border-radius: 50px;
      font-weight: 800;
      text-transform: uppercase;
      font-size: 0.9rem;
      letter-spacing: 1px;
      background: rgba(255,255,255,0.2);
      border: 2px solid white;
      margin-top: 1rem;
    }

    .main-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
      gap: 1.5rem;
      margin-bottom: 2rem;
    }

    .card {
      background: white;
      border-radius: 12px;
      padding: 1.5rem;
      box-shadow: 0 2px 12px rgba(0,0,0,0.08);
      transition: transform 0.2s;
    }
    
    .card:hover { transform: translateY(-5px); }

    .risk-score {
      font-size: 4rem;
      font-weight: 900;
      text-align: center;
      margin: 1rem 0;
    }

    .risk-label {
      text-align: center;
      text-transform: uppercase;
      font-weight: 700;
      color: #606770;
      font-size: 0.8rem;
    }

    .stat-row {
      display: flex;
      justify-content: space-between;
      padding: 0.75rem 0;
      border-bottom: 1px solid #ebedf0;
    }

    .stat-row:last-child { border-bottom: none; }

    .stat-label { font-weight: 600; color: #4b4f56; }
    .stat-value { font-weight: 700; }

    .section-title {
      font-size: 1.5rem;
      font-weight: 700;
      margin: 2rem 0 1rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .section-title::before {
      content: '';
      width: 4px;
      height: 1.5rem;
      background: #b21f1f;
      border-radius: 2px;
    }

    #graph-container {
      background: white;
      border-radius: 12px;
      height: 800px;
      box-shadow: 0 2px 12px rgba(0,0,0,0.08);
      overflow: hidden;
      position: relative;
      margin-bottom: 2rem;
    }

    svg { width: 100%; height: 100%; cursor: grab; }
    svg:active { cursor: grabbing; }

    .controls {
      position: absolute;
      top: 20px;
      right: 20px;
      display: flex;
      gap: 0.5rem;
      z-index: 10;
    }

    .control-btn {
      padding: 0.5rem 1rem;
      background: white;
      border: 1px solid #ebedf0;
      border-radius: 6px;
      cursor: pointer;
      font-weight: 600;
      font-size: 0.8rem;
      box-shadow: 0 2px 4px rgba(0,0,0,0.05);
      transition: all 0.2s;
    }

    .control-btn:hover { background: #f5f6f7; }
    .control-btn.active { background: #1a2a6c; color: white; border-color: #1a2a6c; }

    .remediation-table {
      width: 100%;
      border-collapse: collapse;
      background: white;
      border-radius: 12px;
      overflow: hidden;
      box-shadow: 0 2px 12px rgba(0,0,0,0.08);
      margin-bottom: 2rem;
    }

    .remediation-table th {
      background: #f5f6f7;
      text-align: left;
      padding: 1rem;
      font-weight: 700;
      border-bottom: 2px solid #ebedf0;
    }

    .remediation-table td {
      padding: 1rem;
      border-bottom: 1px solid #ebedf0;
      vertical-align: top;
    }

    .priority-badge {
      padding: 0.25rem 0.75rem;
      border-radius: 4px;
      font-weight: 700;
      font-size: 0.75rem;
    }

    .priority-Immediate { background: #ffebee; color: #c62828; }
    .priority-High { background: #fff3e0; color: #e65100; }
    .priority-Medium { background: #e3f2fd; color: #1565c0; }
    .priority-Low { background: #e8f5e9; color: #2e7d32; }

    .node circle { stroke-width: 2px; cursor: pointer; transition: all 0.2s; }
    .node:hover circle { stroke-width: 4px; filter: brightness(1.1); }
    .node text { font-size: 10px; font-weight: 600; pointer-events: none; }

    .link { fill: none; stroke: #ccd0d5; stroke-width: 1.5px; stroke-opacity: 0.4; }

    .node.route circle { r: 14; }
    .node.auth circle { r: 12; fill: #ffd43b; stroke: #fab005; }
    .node.handler circle { r: 12; fill: #ccd0d5; stroke: #8d949e; }
    .node.vulnerable circle { fill: #ff3b30; stroke: #c62828; }
    .node.safe circle { fill: #34c759; stroke: #2e7d32; }

    .tooltip {
      position: absolute;
      background: rgba(0,0,0,0.9);
      color: white;
      padding: 12px;
      border-radius: 8px;
      font-size: 13px;
      pointer-events: none;
      z-index: 1000;
      display: none;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
      max-width: 300px;
    }

    .legend {
      position: absolute;
      bottom: 20px;
      left: 20px;
      background: rgba(255,255,255,0.9);
      padding: 12px;
      border-radius: 8px;
      font-size: 0.75rem;
      box-shadow: 0 2px 8px rgba(0,0,0,0.1);
      z-index: 10;
    }
    
    .legend-item { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
    .legend-dot { width: 10px; height: 10px; border-radius: 50%; }

    footer {
      text-align: center;
      padding: 2rem;
      color: #606770;
      font-size: 0.85rem;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Web-Wreck Phase 4 Security Report</h1>
      <p>Source-Code Based Semantic Analysis for Node.js/Express</p>
      <div class="status-badge" style="border-color: ${report.overallStatus === 'Secure' ? '#34c759' : '#ff3b30'}">
        Status: ${report.overallStatus}
      </div>
    </div>

    <div class="main-grid">
      <div class="card">
        <div class="risk-label">Application Risk Score</div>
        <div class="risk-score" style="color: ${report.summary.riskScore > 70 ? '#ff3b30' : (report.summary.riskScore > 40 ? '#ff9500' : '#34c759')}">
          ${report.summary.riskScore}
        </div>
        <div class="risk-label">${report.overallStatus} Risk</div>
      </div>
      
      <div class="card">
        <h3 style="margin-bottom: 1rem;">Findings Overview</h3>
        <div class="stat-row">
          <span class="stat-label">Critical Findings</span>
          <span class="stat-value" style="color: #ff3b30">${report.summary.criticalIssues}</span>
        </div>
        <div class="stat-row">
          <span class="stat-label">High Priority</span>
          <span class="stat-value" style="color: #ff9500">${report.summary.highIssues}</span>
        </div>
        <div class="stat-row">
          <span class="stat-label">Total Findings</span>
          <span class="stat-value">${report.summary.totalFindings}</span>
        </div>
        <div class="stat-row">
          <span class="stat-label">Complexity</span>
          <span class="stat-value">${report.summary.remediationComplexity.toUpperCase()}</span>
        </div>
      </div>

      <div class="card">
        <h3 style="margin-bottom: 1rem;">Project Stats</h3>
        <div class="stat-row">
          <span class="stat-label">Analyzed Routes</span>
          <span class="stat-value">${graph.routes.length}</span>
        </div>
        <div class="stat-row">
          <span class="stat-label">Execution Nodes</span>
          <span class="stat-value">${graph.nodes.size}</span>
        </div>
        <div class="stat-row">
          <span class="stat-label">Auth Components</span>
          <span class="stat-value">${analysis.authNodes.length}</span>
        </div>
        <div class="stat-row">
          <span class="stat-label">Analyzed at</span>
          <span class="stat-value">${now}</span>
        </div>
      </div>
    </div>

    <h2 class="section-title">Critical Path Visualization</h2>
    <div id="graph-container">
      <div class="controls">
        <button class="control-btn active" onclick="setLayout('tree')">Tree Map</button>
        <button class="control-btn" onclick="setLayout('force')">Force Flow</button>
        <button class="control-btn" onclick="resetZoom()">Reset</button>
        <button class="control-btn" onclick="fitToScreen()">Fit</button>
      </div>
      <svg id="viz-svg"></svg>
      <div class="legend">
        <div class="legend-item"><div class="legend-dot" style="background: #ff3b30"></div> Vulnerable Route</div>
        <div class="legend-item"><div class="legend-dot" style="background: #34c759"></div> Protected Route</div>
        <div class="legend-item"><div class="legend-dot" style="background: #ffd43b"></div> Auth Middleware</div>
        <div class="legend-item"><div class="legend-dot" style="background: #ccd0d5"></div> Custom Handler</div>
      </div>
    </div>

    <h2 class="section-title">Remediation Action Plan</h2>
    <table class="remediation-table">
      <thead>
        <tr>
          <th>Priority</th>
          <th>Issue</th>
          <th>Remediation Action</th>
        </tr>
      </thead>
      <tbody>
        ${report.prioritizedFindings.slice(0, 15).map(f => `
          <tr>
            <td><span class="priority-badge priority-${f.severity === 'critical' ? 'Immediate' : (f.severity === 'high' ? 'High' : (f.severity === 'medium' ? 'Medium' : 'Low'))}">${f.severity === 'critical' ? 'Immediate' : f.severity.charAt(0).toUpperCase() + f.severity.slice(1)}</span></td>
            <td><strong>${f.message}</strong></td>
            <td>${f.remediation}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>

    <footer>
      <p>Generated by <strong>Web-Wreck v0.0.2</strong> • Analysis of ${graph.routes.length} paths complete.</p>
    </footer>
  </div>

  <div id="tooltip" class="tooltip"></div>

  <script>
    const graphData = ${JSON.stringify(treeData)};
    let currentLayout = 'tree';
    let svg, g, zoom, simulation;

    function initGraph() {
      const container = d3.select('#viz-svg');
      const width = document.getElementById('graph-container').clientWidth;
      const height = 800;
      
      svg = d3.select('#viz-svg')
        .attr('viewBox', [0, 0, width, height]);
      
      g = svg.append('g');
      
      zoom = d3.zoom()
        .scaleExtent([0.1, 4])
        .on('zoom', (event) => {
          g.attr('transform', event.transform);
        });
      
      svg.call(zoom);
      renderTreeLayout();
    }

    function renderTreeLayout() {
      g.selectAll('*').remove();
      const width = document.getElementById('graph-container').clientWidth;
      const height = 800;
      
      const treeLayout = d3.tree()
        .size([height - 100, width - 350])
        .separation((a, b) => (a.parent === b.parent ? 1 : 1.5));
      
      const root = d3.hierarchy(graphData);
      treeLayout(root);
      
      const link = g.selectAll('.link')
        .data(root.links())
        .join('path')
        .attr('class', 'link')
        .attr('d', d3.linkHorizontal()
          .x(d => d.y + 100)
          .y(d => d.x + 50));
      
      const node = g.selectAll('.node')
        .data(root.descendants())
        .join('g')
        .attr('class', d => 'node ' + d.data.type + ' ' + (d.data.vulnerable ? 'vulnerable' : (d.data.safe ? 'safe' : '')))
        .attr('transform', d => 'translate(' + (d.y + 100) + ',' + (d.x + 50) + ')')
        .on('mouseover', showTooltip)
        .on('mouseout', hideTooltip);
      
      node.append('circle');
      
      node.append('text')
        .attr('dy', 25)
        .attr('text-anchor', 'middle')
        .text(d => d.data.name.length > 20 ? d.data.name.substring(0, 17) + '...' : d.data.name);
      
      setTimeout(() => fitToScreen(), 100);
    }

    function renderForceLayout() {
      g.selectAll('*').remove();
      const width = document.getElementById('graph-container').clientWidth;
      const height = 800;
      
      const nodes = [];
      const links = [];
      
      function traverse(node, parent = null) {
        nodes.push(node.data);
        if (parent) links.push({ source: parent.data.id, target: node.data.id });
        if (node.children) node.children.forEach(child => traverse(child, node));
      }
      
      traverse(d3.hierarchy(graphData));
      
      simulation = d3.forceSimulation(nodes)
        .force('link', d3.forceLink(links).id(d => d.id).distance(100))
        .force('charge', d3.forceManyBody().strength(-400))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide().radius(50));
      
      const link = g.selectAll('.link')
        .data(links)
        .join('line')
        .attr('class', 'link');
      
      const node = g.selectAll('.node')
        .data(nodes)
        .join('g')
        .attr('class', d => 'node ' + d.type + ' ' + (d.vulnerable ? 'vulnerable' : (d.safe ? 'safe' : '')))
        .call(d3.drag()
          .on('start', dragstarted)
          .on('drag', dragged)
          .on('end', dragended))
        .on('mouseover', showTooltip)
        .on('mouseout', hideTooltip);
      
      node.append('circle');
      
      node.append('text')
        .attr('dy', 25)
        .attr('text-anchor', 'middle')
        .text(d => d.name.length > 20 ? d.name.substring(0, 17) + '...' : d.name);
      
      simulation.on('tick', () => {
        link
          .attr('x1', d => d.source.x)
          .attr('y1', d => d.source.y)
          .attr('x2', d => d.target.x)
          .attr('y2', d => d.target.y);
        
        node.attr('transform', d => 'translate(' + d.x + ',' + d.y + ')');
      });
    }

    function dragstarted(event, d) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      d.fx = d.x; d.fy = d.y;
    }
    function dragged(event, d) { d.fx = event.x; d.fy = event.y; }
    function dragended(event, d) {
      if (!event.active) simulation.alphaTarget(0);
      d.fx = null; d.fy = null;
    }

    function showTooltip(event, d) {
      const tooltip = d3.select('#tooltip');
      const name = d.data ? d.data.name : d.name;
      const type = d.data ? d.data.type : d.type;
      const file = d.data ? d.data.file : d.file;
      
      tooltip.style('display', 'block')
        .style('left', (event.pageX + 15) + 'px')
        .style('top', (event.pageY - 15) + 'px')
        .html('<div style="font-weight: 800; border-bottom: 1px solid rgba(255,255,255,0.2); padding-bottom: 5px; margin-bottom: 8px;">' + name + '</div>' +
              '<div style="font-size: 11px; opacity: 0.9;"><strong>Type:</strong> ' + type + '<br>' +
              (file ? '<strong>Source:</strong> ' + file.split(/[\\\\/]/).pop() : '') + '</div>');
    }

    function hideTooltip() { d3.select('#tooltip').style('display', 'none'); }

    function setLayout(layout) {
      currentLayout = layout;
      document.querySelectorAll('.control-btn').forEach(btn => btn.classList.remove('active'));
      event.target.classList.add('active');
      if (simulation) simulation.stop();
      if (layout === 'tree') renderTreeLayout(); else renderForceLayout();
    }

    function resetZoom() {
      svg.transition().duration(750).call(zoom.transform, d3.zoomIdentity);
    }

    function fitToScreen() {
      const bounds = g.node().getBBox();
      const parent = svg.node().parentElement;
      const width = parent.clientWidth;
      const height = parent.clientHeight;
      const fullWidth = bounds.width;
      const fullHeight = bounds.height;
      const midX = bounds.x + fullWidth / 2;
      const midY = bounds.y + fullHeight / 2;
      const scale = 0.85 / Math.max(fullWidth / width, fullHeight / height);
      const translate = [width / 2 - scale * midX, height / 2 - scale * midY];
      
      svg.transition().duration(750).call(
        zoom.transform,
        d3.zoomIdentity.translate(translate[0], translate[1]).scale(scale)
      );
    }

    initGraph();
  </script>
</body>
</html>`;
}

function generateTreeData(graph: ExecutionGraph, analysis: AuthAnalysis): any {
  const root = {
    id: 'root',
    name: 'Application Entry',
    type: 'root',
    children: [] as any[]
  };

  const adjacency = buildAdjacency(graph);

  graph.routes.forEach(route => {
    const isVulnerable = analysis.unauthenticated.includes(route.id);
    const isProtected = !isVulnerable && analysis.authNodes.length > 0;

    const routeNode = {
      id: route.id,
      name: route.method + ' ' + route.path,
      type: 'route',
      vulnerable: isVulnerable,
      safe: isProtected,
      file: route.sourceLocation.filePath,
      children: [] as any[]
    };

    // Build chain for this route
    const chain = getOrderedExecutionChain(graph, adjacency, route.entryNodeId);

    let currentLevel = routeNode.children;
    chain.forEach((node: any) => {
      const leaf = {
        id: node.id + '-' + route.id, // Unique ID for tree
        name: node.name,
        type: node.type,
        file: node.metadata.sourceLocation.filePath,
        children: [] as any[]
      };
      currentLevel.push(leaf);
      currentLevel = leaf.children;
    });

    root.children.push(routeNode);
  });

  return root;
}

// Helper functions duplicated to avoid complex imports in template
function buildAdjacency(graph: ExecutionGraph): Map<string, string[]> {
  const adjacency = new Map<string, string[]>();
  for (const [nodeId] of graph.nodes) adjacency.set(nodeId, []);
  for (const edge of graph.edges) {
    const neighbors = adjacency.get(edge.from) ?? [];
    neighbors.push(edge.to);
    adjacency.set(edge.from, neighbors);
  }
  return adjacency;
}

function getOrderedExecutionChain(graph: ExecutionGraph, adjacency: Map<string, string[]>, startNodeId: string): any[] {
  const visited = new Set<string>();
  const result: any[] = [];
  function dfs(nodeId: string) {
    if (visited.has(nodeId)) return;
    visited.add(nodeId);
    const node = graph.nodes.get(nodeId);
    if (node) result.push(node);
    const neighbors = adjacency.get(nodeId) ?? [];
    for (const next of neighbors) dfs(next);
  }
  dfs(startNodeId);
  return result;
}