# Web-Wreck — Architecture Diagram

## System Overview

```mermaid
graph TB
    subgraph CLI["CLI Entry Point"]
        INDEX["index.ts<br/>─────────────<br/>Orchestrator<br/>argv parsing<br/>Pipeline coordinator"]
    end

    subgraph PHASE1["Phase 1: Source Ingestion"]
        direction TB
        SCAN_INDEX["scan/index.ts<br/>─────────────<br/>scanRepository()"]
        CLONE["scan/clone.ts<br/>─────────────<br/>cloneRepository()<br/>simple-git --depth 1"]
        FILES["scan/files.ts<br/>─────────────<br/>discoverSourceFiles()<br/>Recursive walk<br/>Filters: .js .ts .jsx .tsx<br/>Ignores: node_modules, dist, etc."]
        
        SCAN_INDEX --> CLONE
        SCAN_INDEX --> FILES
    end

    subgraph PHASE2["Phase 2: AST Parsing"]
        direction TB
        PARSER_INDEX["parser/index.ts<br/>─────────────<br/>parseFiles()<br/>Defines: RouteDefinition<br/>Defines: FunctionReference"]
        AST["parser/ast.ts<br/>─────────────<br/>parseFileToAST()<br/>@babel/parser<br/>Plugins: TS, JSX, decorators,<br/>optional chaining, etc."]
        EXPRESS["parser/express.ts<br/>─────────────<br/>extractExpressRoutes()<br/>JWT/Passport/Session detection<br/>req.user, next(), role extraction<br/>Conditional auth patterns"]
        
        PARSER_INDEX --> AST
        PARSER_INDEX --> EXPRESS
    end

    subgraph PHASE3["Phase 3: IR Construction"]
        direction TB
        TYPES["ir/types.ts<br/>─────────────<br/>ExecutionGraph<br/>ExecutionNode<br/>Edge, Route<br/>SecurityFinding<br/>NodeKind, AuthType<br/>AuthEnforcement<br/>Severity, FindingType"]
        BUILD["ir/build.ts<br/>─────────────<br/>buildExecutionGraph()<br/>classifyNode()<br/>createNode()<br/>Edge condition logic"]
        VALIDATE["ir/validate.ts<br/>─────────────<br/>validateGraph()<br/>Node reference checks<br/>Edge integrity checks"]
        
        BUILD --> TYPES
        VALIDATE --> TYPES
    end

    subgraph PHASE4["Phase 4: Security Analysis"]
        direction TB
        AUTH["analyze/authPresence.ts<br/>─────────────<br/>analyzeAuthPresence()<br/>Auth chain analysis<br/>Public route whitelist<br/>Privileged route detection<br/>Bypass path identification<br/>CWE classification"]
        FINDINGS["analyze/findings.ts<br/>─────────────<br/>generateFindingReport()<br/>exportFindingsMarkdown()<br/>By-route / by-node / by-severity<br/>grouping"]
        REPORT["analyze/report.ts<br/>─────────────<br/>generateSecurityReport()<br/>Risk scoring algorithm<br/>Deduplication<br/>Remediation plan<br/>Executive summary"]
        ANALYZE_INDEX["analyze/index.ts<br/>─────────────<br/>Module re-exports"]
        
        ANALYZE_INDEX --> AUTH
        ANALYZE_INDEX --> FINDINGS
        ANALYZE_INDEX --> REPORT
    end

    subgraph PHASE5["Phase 5: Output Generation"]
        direction TB
        JSON_OUT["graph/json.ts<br/>─────────────<br/>outputJson()<br/>Structured JSON with<br/>executive summary,<br/>route findings,<br/>remediation plan"]
        MERMAID_OUT["graph/graph.ts<br/>─────────────<br/>outputMermaid()<br/>Flowchart generation<br/>CSS class annotations"]
        HTML_OUT["output/visualize.ts<br/>─────────────<br/>outputHtml()<br/>Cytoscape.js tree<br/>Interactive tooltip<br/>Search & Filters<br/>Remediation table"]
        GRAPH_INDEX["graph/index.ts<br/>─────────────<br/>Re-exports"]
        
        GRAPH_INDEX --> JSON_OUT
        GRAPH_INDEX --> MERMAID_OUT
    end

    subgraph UTIL["Utilities"]
        LOG["util/log.ts<br/>─────────────<br/>log.phase()<br/>log.info/warn/error<br/>log.success()"]
        TEMP["util/temp.ts<br/>─────────────<br/>createTempDir()<br/>cleanupTempDir()"]
    end

    subgraph OUTPUT_FILES["Generated Reports"]
        HTML_FILE["report-YYYY-MM-DD-XXXX.html"]
        MD_FILE["report-YYYY-MM-DD-XXXX.md"]
        JSON_STDOUT["JSON → stdout"]
        MERMAID_STDOUT["Mermaid → stdout"]
    end

    %% Main pipeline flow
    INDEX ==>|"repoUrl"| SCAN_INDEX
    SCAN_INDEX ==>|"ScanResult {repoPath, files[]}"| PARSER_INDEX
    PARSER_INDEX ==>|"ParsedFile[]"| BUILD
    BUILD ==>|"ExecutionGraph"| ANALYZE_INDEX
    ANALYZE_INDEX ==>|"AuthAnalysis + SecurityReport"| GRAPH_INDEX
    ANALYZE_INDEX ==>|"AuthAnalysis + SecurityReport"| HTML_OUT
    ANALYZE_INDEX ==>|"AuthAnalysis"| FINDINGS
    GRAPH_INDEX ==>|"JSON string"| JSON_STDOUT
    GRAPH_INDEX ==>|"Mermaid string"| MERMAID_STDOUT
    HTML_OUT ==>|"HTML string"| HTML_FILE
    FINDINGS ==>|"Markdown string"| MD_FILE

    %% Utility connections
    SCAN_INDEX -.->|"logging"| LOG
    CLONE -.->|"temp dir"| TEMP
    INDEX -.->|"logging"| LOG

    %% Styling for better readability (black text in light boxes)
    classDef phase1 fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:#000
    classDef phase2 fill:#fce4ec,stroke:#c62828,stroke-width:2px,color:#000
    classDef phase3 fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px,color:#000
    classDef phase4 fill:#fff3e0,stroke:#e65100,stroke-width:2px,color:#000
    classDef phase5 fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#000
    classDef util fill:#eceff1,stroke:#546e7a,stroke-width:1px,color:#000
    classDef output fill:#fffde7,stroke:#f9a825,stroke-width:2px,color:#000
    classDef entry fill:#1a2a6c,stroke:#0d1536,stroke-width:3px,color:#fff

    class INDEX entry
    class SCAN_INDEX,CLONE,FILES phase1
    class PARSER_INDEX,AST,EXPRESS phase2
    class TYPES,BUILD,VALIDATE phase3
    class AUTH,FINDINGS,REPORT,ANALYZE_INDEX phase4
    class JSON_OUT,MERMAID_OUT,HTML_OUT,GRAPH_INDEX phase5
    class LOG,TEMP util
    class HTML_FILE,MD_FILE,JSON_STDOUT,MERMAID_STDOUT output
```

---

## Data Flow Summary

```mermaid
flowchart LR
    A["GitHub URL"] --> B["Clone<br/>(simple-git)"]
    B --> C["File Discovery<br/>(.js/.ts/.jsx/.tsx)"]
    C --> D["Babel AST<br/>Parsing"]
    D --> E["Express Route<br/>Extraction"]
    E --> F["IR Graph<br/>Construction"]
    F --> G["Auth Presence<br/>Analysis"]
    G --> H["Security<br/>Reporting"]
    H --> I["HTML / MD /<br/>JSON / Mermaid"]

    style A fill:#e3f2fd,stroke:#1565c0,color:#000
    style B fill:#e3f2fd,stroke:#1565c0,color:#000
    style C fill:#e3f2fd,stroke:#1565c0,color:#000
    style D fill:#fce4ec,stroke:#c62828,color:#000
    style E fill:#fce4ec,stroke:#c62828,color:#000
    style F fill:#f3e5f5,stroke:#7b1fa2,color:#000
    style G fill:#fff3e0,stroke:#e65100,color:#000
    style H fill:#fff3e0,stroke:#e65100,color:#000
    style I fill:#e8f5e9,stroke:#2e7d32,color:#000
```

---

## IR Graph Structure (Execution Model)

```mermaid
graph LR
    subgraph "Route: GET /admin/users"
        R1["Route Entry<br/>GET /admin/users"] --> MW1["auth middleware<br/>(type: auth)<br/>enforcement: hard"]
        MW1 -->|"on-success"| MW2["roleCheck<br/>(type: auth)<br/>roles: admin"]
        MW2 -->|"on-success"| H1["listUsers<br/>(type: handler)"]
    end

    subgraph "Route: POST /login"
        R2["Route Entry<br/>POST /login"] --> H2["loginHandler<br/>(type: handler)"]
    end

    subgraph "Route: GET /profile"
        R3["Route Entry<br/>GET /profile"] --> MW3["optionalAuth<br/>(type: auth)<br/>enforcement: conditional"]
        MW3 -->|"conditional"| H3["getProfile<br/>(type: handler)"]
    end

    style R1 fill:#ff3b30,stroke:#c62828,color:#fff
    style R2 fill:#74c0fc,stroke:#1864ab,color:#000
    style R3 fill:#ff9500,stroke:#e65100,color:#000
    style MW1 fill:#ffd43b,stroke:#fab005,color:#000
    style MW2 fill:#ffd43b,stroke:#fab005,color:#000
    style MW3 fill:#ffd43b,stroke:#fab005,color:#000
    style H1 fill:#ccd0d5,stroke:#8d949e,color:#000
    style H2 fill:#ccd0d5,stroke:#8d949e,color:#000
    style H3 fill:#ccd0d5,stroke:#8d949e,color:#000
```

---

## Security Analysis Decision Tree

```mermaid
flowchart TD
    START["Analyze Route Chain"] --> HAS_AUTH{"Has auth nodes<br/>in chain?"}
    
    HAS_AUTH -->|No| IS_PUBLIC{"Is public route?<br/>(health, login, etc.)"}
    IS_PUBLIC -->|Yes| INFO["Severity: INFO<br/>Public endpoint"]
    IS_PUBLIC -->|No| IS_AUTH_FLOW{"Is auth flow?<br/>(login, register)"}
    IS_AUTH_FLOW -->|Yes| INFO2["Severity: INFO<br/>Auth flow endpoint"]
    IS_AUTH_FLOW -->|No| IS_ROUTER{"Is router mount?<br/>(app.use)"}
    IS_ROUTER -->|Yes| INFO3["Severity: INFO<br/>Router mount"]
    IS_ROUTER -->|No| IS_PRIV{"Is privileged<br/>route?"}
    IS_PRIV -->|Yes| CRIT["Severity: CRITICAL<br/>CWE-306<br/>Risk: 90"]
    IS_PRIV -->|No| MED["Severity: MEDIUM<br/>CWE-306<br/>Risk: 40"]

    HAS_AUTH -->|Yes| CHECK_ORDER{"Auth before<br/>handler?"}
    CHECK_ORDER -->|No| ORDER_BUG["Severity: CRITICAL<br/>CWE-863<br/>Auth after handler<br/>Risk: 95"]
    CHECK_ORDER -->|Yes| CHECK_COND{"Conditional<br/>auth?"}
    CHECK_COND -->|Yes| COND_WARN["Severity: HIGH<br/>CWE-285<br/>Bypass risk<br/>Risk: 75"]
    CHECK_COND -->|No| CHECK_ENFORCE{"Enforcement<br/>level?"}
    CHECK_ENFORCE -->|Soft| SOFT_WARN["Severity: HIGH<br/>CWE-306<br/>Weak auth<br/>Risk: 65"]
    CHECK_ENFORCE -->|Hard| CHECK_RBAC{"Privileged +<br/>missing RBAC?"}
    CHECK_RBAC -->|Yes| RBAC_WARN["Severity: CRITICAL<br/>CWE-862<br/>Missing RBAC<br/>Risk: 85"]
    CHECK_RBAC -->|No| SAFE["Route is<br/>properly protected"]

    style CRIT fill:#ff3b30,stroke:#c62828,color:#fff
    style ORDER_BUG fill:#ff3b30,stroke:#c62828,color:#fff
    style RBAC_WARN fill:#ff3b30,stroke:#c62828,color:#fff
    style COND_WARN fill:#ff9500,stroke:#e65100,color:#000
    style SOFT_WARN fill:#ff9500,stroke:#e65100,color:#000
    style MED fill:#ffcc02,stroke:#b8860b,color:#000
    style INFO fill:#34c759,stroke:#2e7d32,color:#fff
    style INFO2 fill:#34c759,stroke:#2e7d32,color:#fff
    style INFO3 fill:#34c759,stroke:#2e7d32,color:#fff
    style SAFE fill:#34c759,stroke:#2e7d32,color:#fff
```

---

## File System Layout

```
web-wreck/
├── backend/
│   ├── src/
│   │   ├── index.ts              ← CLI entry point & pipeline orchestrator
│   │   ├── scan/
│   │   │   ├── index.ts          ← scanRepository() orchestrator
│   │   │   ├── clone.ts          ← Git clone (simple-git)
│   │   │   └── files.ts          ← Recursive file discovery
│   │   ├── parser/
│   │   │   ├── index.ts          ← parseFiles() + type definitions
│   │   │   ├── ast.ts            ← Babel AST parsing
│   │   │   ├── express.ts        ← Express route extraction
│   │   │   └── resolve.ts        ← Cross-file reference resolution
│   │   ├── ir/
│   │   │   ├── types.ts          ← All IR type definitions
│   │   │   ├── build.ts          ← ExecutionGraph builder
│   │   │   └── validate.ts       ← Graph structural validation
│   │   ├── analyze/
│   │   │   ├── index.ts          ← Module re-exports
│   │   │   ├── authPresence.ts   ← Auth analysis engine
│   │   │   ├── findings.ts       ← Finding management
│   │   │   └── report.ts         ← Security report generator
│   │   ├── graph/
│   │   │   ├── index.ts          ← Re-exports
│   │   │   ├── json.ts           ← JSON output serialization
│   │   │   └── graph.ts          ← Mermaid diagram generation
│   │   ├── output/
│   │   │   └── visualize.ts      ← HTML + Cytoscape visualization
│   │   └── util/
│   │       ├── graph.ts          ← Graph traversal utils (DFS, etc.)
│   │       ├── log.ts            ← Logging utilities
│   │       └── temp.ts           ← Temp directory management
│   ├── dist/                     ← Compiled JS output
│   ├── package.json
│   ├── tsconfig.json
│   ├── ARCHITECTURE.md           ← This architecture document
│   └── SETUP.md                  ← Setup and usage guide
├── web-wreck-output/             ← Generated reports
│   └── report-YYYY-MM-DD-XXXX.html
└── package.json                  ← Root dependencies
```
