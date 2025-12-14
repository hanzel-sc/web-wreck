# Web-Wreck

Web-Wreck is an experimental static analysis tool that maps authentication and authorization flows in web applications by extracting route, middleware, and controller execution paths directly from source code.

The project focuses on a class of security issues that traditional SAST and DAST tools struggle with: broken or missing authentication logic caused by incorrect control flow, middleware ordering, or inconsistent protection of routes.

---

## Why Web-Wreck ?

This tool would help vibe-coders, college students and beginner web developers build applications with better auth flow, help them understand simple security and auth mechanisms visually. 

Authentication and authorization failures are rarely caused by syntax errors. They are usually logic bugs. 

Examples include:
- routes accessible without authentication
- misordered middleware that allows bypass
- inconsistent protection across similar endpoints
- missing authorization checks on privileged routes

These issues are often invisible to automated scanners and are usually discovered through manual code review. Web-Wreck aims to make these flaws visible by modeling request execution paths as a graph/tree. 

---

## What Web-Wreck Does

#### v.0.0.1
- Clones a public GitHub repository for analysis
- Statistically parses JavaScript and TypeScript source files
- Detects Express-style route definitions
- Extracts middleware and controller chains
- Builds a directed execution graph representing request flow
- Heuristically identifies authentication-related middleware
- Highlights routes and paths that lack authentication

This project is in early development and is intentionally limited in scope. The current focus is on correctness and clarity of flow extraction rather than exhaustive vulnerability detection. 

---

## Current Scope 

#### v.0.0.1
- Node.js applications
- Express-style routing
- Static analysis only
- Public repositories only
- Heuristic-based authentication detection

---

## How It Works

1. The repository is cloned into a temporary workspace
2. Source files are parsed into ASTs
3. Route definitions are extracted
4. Middleware and controller chains are resolved
5. Execution paths are modeled as a directed graph
6. Authentication presence is annotated
7. The graph is output in a structured format

Visualization and reporting are layered on top of this core model.

---

## Tech Stack

- Language: TypeScript
- Runtime: Node.js
- Parsing: @babel/parser, @babel/traverse
- Git handling: simple-git
- Graph model: custom lightweight DAG representation

The analysis engine is framework-agnostic by design and will be extended incrementally.

---

## Roadmap

### Phase 1 — Core Flow Extraction (In Progress)
- [ ] Clone and index public GitHub repositories
- [ ] Traverse project directories and collect JS/TS source files
- [ ] Parse source files into ASTs using Babel
- [ ] Detect Express-style route definitions
- [ ] Extract middleware and controller execution chains
- [ ] Build a directed execution graph (route → middleware → controller)
- [ ] Identify authentication-related middleware using heuristics
- [ ] Flag routes without authentication
- [ ] Output execution graph as structured JSON

### Phase 2 — Visualization
- [ ] Define graph export format (framework-agnostic)
- [ ] Render execution graphs using Mermaid or Cytoscape
- [ ] Visually highlight unauthenticated and weakly protected routes
- [ ] Add basic graph navigation (zoom, pan)
- [ ] Add legend and flow indicators

### Phase 3 — Authentication Semantics
- [ ] Detect JWT verification usage
- [ ] Identify missing or incorrect token validation
- [ ] Validate middleware ordering for authentication enforcement
- [ ] Differentiate global vs route-level authentication
- [ ] Detect basic role-based access control patterns
- [ ] Identify authentication bypass paths through graph traversal

### Phase 4 — Security Reporting
- [ ] Associate security findings with graph nodes
- [ ] Classify findings by severity
- [ ] Generate human-readable issue summaries
- [ ] Provide remediation hints for common auth flaws
- [ ] Export reports in JSON and Markdown formats

### Phase 5 — Tooling Integration
- [ ] Add CLI options for configurable scans
- [ ] Support CI-friendly output modes
- [ ] Integrate with GitHub Actions
- [ ] Enable incremental scanning for updated repositories

### Phase 6 — Framework and Language Expansion
- [ ] Support Fastify
- [ ] Support NestJS
- [ ] Support Next.js API routes
- [ ] Explore Python frameworks (Flask, FastAPI)
- [ ] Generalize framework detection and parsing logic
