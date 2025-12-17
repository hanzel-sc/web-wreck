/**
 * HTML visualization output with interactive D3.js graph
 * Generates a standalone HTML file that can be opened in a browser
 */

import type { ExecutionGraph } from '../ir/types.js';
import type { AuthAnalysis } from '../analyze/authPrescence.js';

/**
 * Generate a complete HTML page with interactive D3.js visualization
 */
export function outputHtml(graph: ExecutionGraph, analysis: AuthAnalysis): string {
  const graphData = generateD3GraphData(graph, analysis);
  const routesSummary = generateRoutesSummary(graph, analysis);
  
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Web-Wreck Analysis Report</title>
  <script src="https://d3js.org/d3.v7.min.js"></script>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen',
        'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue', sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      padding: 2rem;
    }
    
    .container {
      max-width: 1600px;
      margin: 0 auto;
      background: white;
      border-radius: 16px;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
      overflow: hidden;
    }
    
    header {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      padding: 2rem;
      text-align: center;
    }
    
    header h1 {
      font-size: 2.5rem;
      margin-bottom: 0.5rem;
      font-weight: 700;
    }
    
    header p {
      font-size: 1.1rem;
      opacity: 0.9;
    }
    
    .stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1.5rem;
      padding: 2rem;
      background: #f8f9fa;
    }
    
    .stat-card {
      background: white;
      padding: 1.5rem;
      border-radius: 12px;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
      text-align: center;
      transition: transform 0.2s;
    }
    
    .stat-card:hover {
      transform: translateY(-4px);
      box-shadow: 0 4px 16px rgba(0, 0, 0, 0.15);
    }
    
    .stat-value {
      font-size: 2.5rem;
      font-weight: 700;
      margin-bottom: 0.5rem;
    }
    
    .stat-label {
      color: #6c757d;
      font-size: 0.9rem;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    
    .stat-card.routes .stat-value { color: #667eea; }
    .stat-card.nodes .stat-value { color: #74c0fc; }
    .stat-card.auth .stat-value { color: #fab005; }
    .stat-card.vulnerable .stat-value { color: #ff6b6b; }
    
    .graph-section {
      padding: 2rem;
    }
    
    .section-title {
      font-size: 1.8rem;
      font-weight: 700;
      margin-bottom: 1.5rem;
      color: #212529;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    
    .section-title::before {
      content: '';
      width: 4px;
      height: 2rem;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      border-radius: 2px;
    }
    
    .controls {
      display: flex;
      gap: 1rem;
      margin-bottom: 1.5rem;
      flex-wrap: wrap;
    }
    
    .control-btn {
      padding: 0.75rem 1.5rem;
      background: white;
      border: 2px solid #667eea;
      color: #667eea;
      border-radius: 8px;
      cursor: pointer;
      font-weight: 600;
      transition: all 0.2s;
      font-size: 0.9rem;
    }
    
    .control-btn:hover {
      background: #667eea;
      color: white;
      transform: translateY(-2px);
      box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);
    }
    
    .control-btn.active {
      background: #667eea;
      color: white;
    }
    
    #graph-container {
      background: #f8f9fa;
      border-radius: 12px;
      border: 2px solid #e9ecef;
      margin-bottom: 2rem;
      overflow: hidden;
      position: relative;
      min-height: 600px;
    }
    
    #graph-svg {
      width: 100%;
      height: 600px;
      cursor: grab;
    }
    
    #graph-svg:active {
      cursor: grabbing;
    }
    
    .legend {
      display: flex;
      gap: 1.5rem;
      flex-wrap: wrap;
      padding: 1.5rem;
      background: #f8f9fa;
      border-radius: 12px;
      margin-bottom: 2rem;
    }
    
    .legend-item {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      font-size: 0.95rem;
    }
    
    .legend-box {
      width: 24px;
      height: 24px;
      border-radius: 6px;
      border: 2px solid;
    }
    
    .legend-box.vulnerable { 
      background: #ff6b6b; 
      border-color: #c92a2a; 
    }
    .legend-box.safe { 
      background: #51cf66; 
      border-color: #2b8a3e; 
    }
    .legend-box.auth { 
      background: #ffd43b; 
      border-color: #fab005; 
    }
    .legend-box.normal { 
      background: #74c0fc; 
      border-color: #1864ab; 
    }
    
    /* D3 Graph Styles */
    .node circle {
      stroke-width: 2.5px;
      cursor: pointer;
      transition: all 0.2s;
    }
    
    .node text {
      font-size: 12px;
      font-weight: 500;
      pointer-events: none;
      user-select: none;
    }
    
    .node:hover circle {
      stroke-width: 4px;
      filter: brightness(1.1);
    }
    
    .link {
      fill: none;
      stroke: #999;
      stroke-width: 2px;
      stroke-opacity: 0.6;
      marker-end: url(#arrowhead);
    }
    
    .link.highlighted {
      stroke: #667eea;
      stroke-width: 3px;
      stroke-opacity: 1;
    }
    
    .node.route circle {
      r: 20;
    }
    
    .node.middleware circle {
      r: 16;
    }
    
    .node.handler circle {
      r: 18;
    }
    
    .node.vulnerable circle {
      fill: #ff6b6b;
      stroke: #c92a2a;
    }
    
    .node.safe circle {
      fill: #51cf66;
      stroke: #2b8a3e;
    }
    
    .node.auth circle {
      fill: #ffd43b;
      stroke: #fab005;
    }
    
    .node.normal circle {
      fill: #74c0fc;
      stroke: #1864ab;
    }
    
    .tooltip {
      position: absolute;
      padding: 12px;
      background: rgba(0, 0, 0, 0.9);
      color: white;
      border-radius: 8px;
      pointer-events: none;
      font-size: 14px;
      z-index: 1000;
      max-width: 300px;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    }
    
    .tooltip-title {
      font-weight: 700;
      margin-bottom: 6px;
      font-size: 15px;
    }
    
    .tooltip-content {
      font-size: 13px;
      line-height: 1.4;
    }
    
    .routes-table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 1rem;
      background: white;
      border-radius: 12px;
      overflow: hidden;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
    }
    
    .routes-table thead {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
    }
    
    .routes-table th,
    .routes-table td {
      padding: 1rem;
      text-align: left;
    }
    
    .routes-table th {
      font-weight: 600;
      text-transform: uppercase;
      font-size: 0.85rem;
      letter-spacing: 0.5px;
    }
    
    .routes-table tbody tr {
      border-bottom: 1px solid #e9ecef;
      transition: background 0.2s;
    }
    
    .routes-table tbody tr:hover {
      background: #f8f9fa;
    }
    
    .routes-table tbody tr:last-child {
      border-bottom: none;
    }
    
    .badge {
      display: inline-block;
      padding: 0.35rem 0.75rem;
      border-radius: 6px;
      font-size: 0.85rem;
      font-weight: 600;
      text-transform: uppercase;
    }
    
    .badge.method {
      background: #667eea;
      color: white;
      min-width: 60px;
      text-align: center;
    }
    
    .badge.auth-yes {
      background: #51cf66;
      color: white;
    }
    
    .badge.auth-no {
      background: #ff6b6b;
      color: white;
    }
    
    .path-cell {
      font-family: 'Monaco', 'Menlo', 'Courier New', monospace;
      color: #495057;
      font-size: 0.9rem;
    }
    
    .file-cell {
      color: #6c757d;
      font-size: 0.85rem;
      max-width: 300px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    
    footer {
      padding: 2rem;
      text-align: center;
      background: #f8f9fa;
      color: #6c757d;
      font-size: 0.9rem;
    }
    
    footer strong {
      color: #667eea;
    }
    
    .empty-state {
      text-align: center;
      padding: 4rem 2rem;
      color: #6c757d;
    }
    
    .empty-state-icon {
      font-size: 4rem;
      margin-bottom: 1rem;
      opacity: 0.5;
    }
    
    .empty-state h3 {
      font-size: 1.5rem;
      margin-bottom: 0.5rem;
      color: #495057;
    }
    
    @media (max-width: 768px) {
      body {
        padding: 1rem;
      }
      
      header h1 {
        font-size: 1.8rem;
      }
      
      .stats {
        grid-template-columns: repeat(2, 1fr);
        gap: 1rem;
      }
      
      .legend {
        flex-direction: column;
        gap: 1rem;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>🔍 Web-Wreck Analysis Report</h1>
      <p>Static Security Analysis for Express Applications</p>
    </header>
    
    <div class="stats">
      <div class="stat-card routes">
        <div class="stat-value">${graph.routes.length}</div>
        <div class="stat-label">Total Routes</div>
      </div>
      <div class="stat-card nodes">
        <div class="stat-value">${graph.nodes.size}</div>
        <div class="stat-label">Execution Nodes</div>
      </div>
      <div class="stat-card auth">
        <div class="stat-value">${analysis.authNodes.length}</div>
        <div class="stat-label">Auth Middleware</div>
      </div>
      <div class="stat-card vulnerable">
        <div class="stat-value">${analysis.unauthenticatedRoutes.length}</div>
        <div class="stat-label">Vulnerable Routes</div>
      </div>
    </div>
    
    <div class="graph-section">
      <h2 class="section-title">Execution Flow Graph</h2>
      
      <div class="legend">
        <div class="legend-item">
          <div class="legend-box vulnerable"></div>
          <span>Vulnerable Route (No Auth)</span>
        </div>
        <div class="legend-item">
          <div class="legend-box safe"></div>
          <span>Protected Route</span>
        </div>
        <div class="legend-item">
          <div class="legend-box auth"></div>
          <span>Auth Middleware</span>
        </div>
        <div class="legend-item">
          <div class="legend-box normal"></div>
          <span>Regular Middleware/Handler</span>
        </div>
      </div>
      
      <div class="controls">
        <button class="control-btn active" onclick="setLayout('tree')">Tree Layout</button>
        <button class="control-btn" onclick="setLayout('force')">Force Layout</button>
        <button class="control-btn" onclick="resetZoom()">Reset Zoom</button>
        <button class="control-btn" onclick="fitToScreen()">Fit to Screen</button>
      </div>
      
      ${graph.routes.length > 0 ? `
      <div id="graph-container">
        <svg id="graph-svg"></svg>
      </div>
      ` : `
      <div class="empty-state">
        <div class="empty-state-icon">📭</div>
        <h3>No Routes Found</h3>
        <p>No Express routes were detected in the scanned repository.</p>
      </div>
      `}
    </div>
    
    <div class="graph-section">
      <h2 class="section-title">Routes Summary</h2>
      ${routesSummary}
    </div>
    
    <footer>
      <p>Generated by <strong>Web-Wreck v0.0.2</strong> • ${new Date().toLocaleString()}</p>
    </footer>
  </div>
  
  <div class="tooltip" id="tooltip" style="display: none;"></div>
  
  <script>
    const graphData = ${graphData};
    let currentLayout = 'tree';
    let svg, g, zoom, simulation;
    
    function initGraph() {
      const container = d3.select('#graph-svg');
      const width = container.node().getBoundingClientRect().width;
      const height = 600;
      
      svg = d3.select('#graph-svg')
        .attr('viewBox', [0, 0, width, height]);
      
      // Define arrow marker
      svg.append('defs').append('marker')
        .attr('id', 'arrowhead')
        .attr('viewBox', '0 -5 10 10')
        .attr('refX', 25)
        .attr('refY', 0)
        .attr('markerWidth', 6)
        .attr('markerHeight', 6)
        .attr('orient', 'auto')
        .append('path')
        .attr('d', 'M0,-5L10,0L0,5')
        .attr('fill', '#999');
      
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
      
      const width = svg.node().getBoundingClientRect().width;
      const height = 600;
      
      const treeLayout = d3.tree()
        .size([height - 100, width - 200])
        .separation((a, b) => (a.parent === b.parent ? 1 : 1.5));
      
      const root = d3.hierarchy(graphData);
      treeLayout(root);
      
      // Draw links
      const link = g.selectAll('.link')
        .data(root.links())
        .join('path')
        .attr('class', 'link')
        .attr('d', d3.linkHorizontal()
          .x(d => d.y + 100)
          .y(d => d.x + 50));
      
      // Draw nodes
      const node = g.selectAll('.node')
        .data(root.descendants())
        .join('g')
        .attr('class', d => \`node \${d.data.nodeType} \${d.data.className}\`)
        .attr('transform', d => \`translate(\${d.y + 100},\${d.x + 50})\`)
        .on('mouseover', showTooltip)
        .on('mouseout', hideTooltip);
      
      node.append('circle')
        .attr('r', d => d.data.nodeType === 'route' ? 20 : (d.data.nodeType === 'handler' ? 18 : 16));
      
      node.append('text')
        .attr('dy', 30)
        .attr('text-anchor', 'middle')
        .text(d => d.data.name.length > 15 ? d.data.name.substring(0, 12) + '...' : d.data.name)
        .style('fill', '#333')
        .style('font-size', '11px');
      
      // Fit initial view
      setTimeout(() => fitToScreen(), 100);
    }
    
    function renderForceLayout() {
      g.selectAll('*').remove();
      
      const width = svg.node().getBoundingClientRect().width;
      const height = 600;
      
      // Flatten hierarchy
      const nodes = [];
      const links = [];
      
      function traverse(node, parent = null) {
        nodes.push(node.data);
        if (parent) {
          links.push({ source: parent.data, target: node.data });
        }
        if (node.children) {
          node.children.forEach(child => traverse(child, node));
        }
      }
      
      const root = d3.hierarchy(graphData);
      traverse(root);
      
      simulation = d3.forceSimulation(nodes)
        .force('link', d3.forceLink(links).id(d => d.id).distance(100))
        .force('charge', d3.forceManyBody().strength(-300))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide().radius(40));
      
      const link = g.selectAll('.link')
        .data(links)
        .join('line')
        .attr('class', 'link');
      
      const node = g.selectAll('.node')
        .data(nodes)
        .join('g')
        .attr('class', d => \`node \${d.nodeType} \${d.className}\`)
        .call(d3.drag()
          .on('start', dragstarted)
          .on('drag', dragged)
          .on('end', dragended))
        .on('mouseover', showTooltip)
        .on('mouseout', hideTooltip);
      
      node.append('circle')
        .attr('r', d => d.nodeType === 'route' ? 20 : (d.nodeType === 'handler' ? 18 : 16));
      
      node.append('text')
        .attr('dy', 30)
        .attr('text-anchor', 'middle')
        .text(d => d.name.length > 15 ? d.name.substring(0, 12) + '...' : d.name)
        .style('fill', '#333')
        .style('font-size', '11px');
      
      simulation.on('tick', () => {
        link
          .attr('x1', d => d.source.x)
          .attr('y1', d => d.source.y)
          .attr('x2', d => d.target.x)
          .attr('y2', d => d.target.y);
        
        node.attr('transform', d => \`translate(\${d.x},\${d.y})\`);
      });
    }
    
    function dragstarted(event, d) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      d.fx = d.x;
      d.fy = d.y;
    }
    
    function dragged(event, d) {
      d.fx = event.x;
      d.fy = event.y;
    }
    
    function dragended(event, d) {
      if (!event.active) simulation.alphaTarget(0);
      d.fx = null;
      d.fy = null;
    }
    
    function showTooltip(event, d) {
      const tooltip = d3.select('#tooltip');
      tooltip.style('display', 'block')
        .style('left', (event.pageX + 15) + 'px')
        .style('top', (event.pageY - 15) + 'px')
        .html(\`
          <div class="tooltip-title">\${d.name}</div>
          <div class="tooltip-content">
            <strong>Type:</strong> \${d.nodeType}<br>
            \${d.method ? \`<strong>Method:</strong> \${d.method}<br>\` : ''}
            \${d.path ? \`<strong>Path:</strong> \${d.path}<br>\` : ''}
            \${d.file ? \`<strong>File:</strong> \${d.file.split(/[\\\\\\/]/).pop()}<br>\` : ''}
            \${d.line ? \`<strong>Line:</strong> \${d.line}\` : ''}
          </div>
        \`);
    }
    
    function hideTooltip() {
      d3.select('#tooltip').style('display', 'none');
    }
    
    function setLayout(layout) {
      currentLayout = layout;
      document.querySelectorAll('.control-btn').forEach(btn => {
        btn.classList.remove('active');
      });
      event.target.classList.add('active');
      
      if (simulation) simulation.stop();
      
      if (layout === 'tree') {
        renderTreeLayout();
      } else {
        renderForceLayout();
      }
    }
    
    function resetZoom() {
      svg.transition().duration(750).call(
        zoom.transform,
        d3.zoomIdentity
      );
    }
    
    function fitToScreen() {
      const bounds = g.node().getBBox();
      const width = svg.node().getBoundingClientRect().width;
      const height = 600;
      const fullWidth = bounds.width;
      const fullHeight = bounds.height;
      const midX = bounds.x + fullWidth / 2;
      const midY = bounds.y + fullHeight / 2;
      
      const scale = 0.9 / Math.max(fullWidth / width, fullHeight / height);
      const translate = [width / 2 - scale * midX, height / 2 - scale * midY];
      
      svg.transition().duration(750).call(
        zoom.transform,
        d3.zoomIdentity.translate(translate[0], translate[1]).scale(scale)
      );
    }
    
    // Initialize on load
    if (graphData.children && graphData.children.length > 0) {
      initGraph();
    }
  </script>
</body>
</html>`;
}

/**
 * Generate D3.js hierarchical data structure
 */
function generateD3GraphData(graph: ExecutionGraph, analysis: AuthAnalysis): string {
  const unauthSet = new Set(analysis.unauthenticatedRoutes);
  const authSet = new Set(analysis.authNodes);
  
  // Build hierarchical structure
  const root = {
    name: 'Application',
    nodeType: 'root',
    className: 'normal',
    children: graph.routes.map(route => {
      const isVulnerable = unauthSet.has(route.id);
      const routeNode = {
        id: route.id,
        name: `${route.method} ${route.path}`,
        nodeType: 'route',
        className: isVulnerable ? 'vulnerable' : 'safe',
        method: route.method,
        path: route.path,
        file: route.sourceLocation.filePath,
        line: route.sourceLocation.line,
        children: [] as any[]
      };
      
      // Build execution chain
      const visited = new Set<string>();
      const queue = [route.entryNodeId];
      
      function buildChain(nodeId: string, parent: any) {
        if (visited.has(nodeId)) return;
        visited.add(nodeId);
        
        const node = graph.nodes.get(nodeId);
        if (!node) return;
        
        const isAuth = authSet.has(nodeId);
        const childNode = {
          id: nodeId,
          name: node.name,
          nodeType: node.type,
          className: isAuth ? 'auth' : 'normal',
          file: node.metadata.sourceLocation.filePath,
          line: node.metadata.sourceLocation.line,
          children: [] as any[]
        };
        
        parent.children.push(childNode);
        
        // Find children
        const outgoing = graph.edges.filter(e => e.from === nodeId);
        outgoing.forEach(edge => {
          buildChain(edge.to, childNode);
        });
      }
      
      buildChain(route.entryNodeId, routeNode);
      
      return routeNode;
    })
  };
  
  return JSON.stringify(root);
}

/**
 * Generate HTML table for routes summary
 */
function generateRoutesSummary(graph: ExecutionGraph, analysis: AuthAnalysis): string {
  if (graph.routes.length === 0) {
    return `
    <div class="empty-state">
      <div class="empty-state-icon">🔍</div>
      <h3>No Routes to Display</h3>
      <p>Start by analyzing a repository with Express routes.</p>
    </div>
    `;
  }
  
  const unauthSet = new Set(analysis.unauthenticatedRoutes);
  
  const rows = graph.routes
    .map(route => {
      const hasAuth = !unauthSet.has(route.id);
      const authBadge = hasAuth 
        ? '<span class="badge auth-yes">Protected</span>'
        : '<span class="badge auth-no">Vulnerable</span>';
      
      return `
      <tr>
        <td><span class="badge method">${route.method}</span></td>
        <td class="path-cell">${route.path}</td>
        <td>${authBadge}</td>
        <td class="file-cell" title="${route.sourceLocation.filePath}">${getFileName(route.sourceLocation.filePath)}</td>
        <td>${route.sourceLocation.line}</td>
      </tr>`;
    })
    .join('');
  
  return `
  <table class="routes-table">
    <thead>
      <tr>
        <th>Method</th>
        <th>Path</th>
        <th>Auth Status</th>
        <th>File</th>
        <th>Line</th>
      </tr>
    </thead>
    <tbody>
      ${rows}
    </tbody>
  </table>
  `;
}

/**
 * Extract filename from full path
 */
function getFileName(filePath: string): string {
  const parts = filePath.split(/[/\\]/);
  return parts[parts.length - 1];
}