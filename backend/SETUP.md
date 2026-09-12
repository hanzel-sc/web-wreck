# Web-Wreck Setup & Usage Guide

Web-Wreck is a static analysis tool that maps authentication and authorization flows in Express.js applications by extracting route definitions, building an execution graph, and identifying security gaps.

---

## Prerequisites

| Dependency | Version | Purpose |
|-----------|---------|---------|
| **Node.js** | v18.0+ | Runtime |
| **npm** | v9.0+ | Package manager (bundled with Node.js) |
| **Git** | v2.0+ | Clones target repositories for analysis |

Verify your setup:

```bash
node --version    # Should output v18.x or higher
npm --version     # Should output v9.x or higher
git --version     # Should output git version 2.x or higher
```

---

## Installation

### From Source

```bash
# Clone the Web-Wreck repository
git clone https://github.com/hanzel-sc/web-wreck.git
cd web-wreck/backend

# Install dependencies
npm install

# Build the TypeScript project
npm run build
```

### Verify Installation

```bash
# Link the CLI tool globally
npm link

# Should print usage information
web-wreck --help
```

Expected output:
```
Usage: web-wreck [options] <repo-url>

Static analysis tool for mapping authentication and authorization flows in
Express.js applications

Arguments:
  repo-url            Public GitHub repository URL to analyze

Options:
  -V, --version       output the version number
  --insecure          Disable SSL certificate verification for git clone (useful behind corporate proxies)
  -o, --output <dir>  Output directory for reports (default: "web-wreck-output")
  --json-only         Output JSON to stdout only (CI-friendly mode)
  --no-html           Skip HTML report generation
  -v, --verbose       Enable verbose logging
  -h, --help          display help for command
```

---

## Usage

### Basic Analysis

Run Web-Wreck against any public GitHub repository containing an Express.js application:

```bash
web-wreck https://github.com/hanzel-sc/iwp-placement-portal
```

Or execute directly via Node:
```bash
node dist/index.js https://github.com/hanzel-sc/iwp-placement-portal
```

### CLI Options

| Option | Description |
|--------|-------------|
| `--insecure` | Bypasses SSL certificate verification during `git clone` (ideal for corporate proxies, VPNs, or self-signed certs) |
| `-o, --output <dir>` | Specifies a custom output directory (defaults to `web-wreck-output`) |
| `--json-only` | Emits raw JSON to `stdout` without generating disk artifacts (ideal for CI/CD pipelines) |
| `--no-html` | Skips HTML interactive report generation and only generates Markdown |
| `-v, --verbose` | Displays detailed AST traversal logs, JSON output, and Mermaid diagrams |

**Example with flags:**
```bash
web-wreck https://github.com/hanzel-sc/iwp-placement-portal --insecure -o ./custom-reports
```

### Development Mode

For development, you can use `tsx` to run TypeScript directly without a build step:

```bash
npm run dev -- https://github.com/username/express-app --insecure
```

### What Happens During Analysis

Web-Wreck executes a 5-phase pipeline:

```
1. Source Ingestion  → Validates URL, clones repo (with SSL flag support), discovers source files
2. AST Parsing       → Parses ASTs, indexes function bodies across files, resolves router mount paths
3. IR Construction   → Builds isolated execution graphs with global middleware prepended
4. Security Analysis → Detects auth gaps, ordering issues, and missing RBAC
5. Output Generation → Produces interactive HTML, Markdown, JSON, and Mermaid reports
```

Each phase is logged to the console with progress indicators. All temporary cloned directories are automatically cleaned up upon completion or failure.

---

## Output

### Generated Files

Reports are written to a `web-wreck-output/` directory in your current working directory:

| File | Format | Description |
|------|--------|-------------|
| `report-YYYY-MM-DD-XXXXXX.html` | HTML | Interactive visualization with D3.js tree graph, risk score dashboard, and remediation table |
| `report-YYYY-MM-DD-XXXXXX.md` | Markdown | Text-based summary of all findings, organized by severity and route |

Additionally, JSON and Mermaid outputs are printed when using `-v / --verbose` or `--json-only`.

### Opening the HTML Report

Open the generated HTML report in any modern browser:

```bash
# macOS
open web-wreck-output/report-*.html

# Linux
xdg-open web-wreck-output/report-*.html

# Windows
start web-wreck-output/report-*.html
```

> **Note**: The HTML report requires an internet connection on first load to fetch D3.js from CDN.

---

## Understanding the Report

### Visualization Legend

| Color | Node Type | Meaning |
|-------|-----------|---------|
| 🔴 Red | Route | **Vulnerable** — missing authentication, flagged as security risk |
| 🟢 Green | Route | **Protected** — has auth middleware in execution chain |
| 🔵 Blue | Route | **Public** — intentionally unauthenticated (login, health, etc.) |
| 🟡 Yellow | Middleware | **Auth middleware** — authentication/authorization component |
| ⚪ Gray | Handler | **Handler** — terminal request handler |
| 🔵 Dark Blue | Root | **App entry** — application root node |

### Visualization Controls

| Button | Action |
|--------|--------|
| **Tree Map** | Hierarchical tree layout (default) |
| **Force Flow** | Physics-based force-directed layout with draggable nodes |
| **Reset** | Reset zoom and pan to default |
| **Fit** | Auto-fit the entire graph within the viewport |

Use **mouse scroll** to zoom and **click + drag** to pan. Hover over any node to see details.

### Finding Severity Levels

| Severity | Risk Score | Meaning | Action Required |
|----------|-----------|---------|-----------------|
| **Critical** | 85–95 | Privileged routes with no authentication, auth-after-handler | Immediate fix required |
| **High** | 65–75 | Conditional or weak authentication, soft enforcement | Fix before release |
| **Medium** | 40–50 | Regular routes missing auth, session fixation risks | Plan remediation |
| **Low** | < 40 | Minor concerns | Monitor |
| **Info** | 0 | Intentionally public endpoints | No action needed |

### CWE References

Findings are mapped to Common Weakness Enumeration (CWE) identifiers:

| CWE | Description | Example Finding |
|-----|-------------|-----------------|
| CWE-306 | Missing Authentication for Critical Function | Route with no auth middleware |
| CWE-862 | Missing Authorization | Privileged route lacking RBAC |
| CWE-863 | Incorrect Authorization | Auth middleware placed after handler |
| CWE-285 | Improper Authorization | Conditional auth allowing bypass |
| CWE-384 | Session Fixation | Session check without regeneration |

---

## Supported Patterns

### Route Definitions & Mount Path Composition

Web-Wreck detects Express-style route definitions and resolves router mounts:

```javascript
// ✅ Route definitions
app.get('/users', authMiddleware, getUsers);
app.post('/login', loginHandler);
router.delete('/users/:id', auth, roleCheck, deleteUser);

// ✅ Router mount path composition
app.use('/api/v1', apiRouter); // router routes like router.get('/items') -> /api/v1/items

// ✅ Global middleware tracking
app.use(authMiddleware); // Tracked and prepended to all route execution chains

// ❌ Not yet detected
router.route('/users').get(getUsers).post(createUser);  // Chained routes
app.get(/regex/, handler);                               // Regex paths
```

### Auth & Security Patterns

The following authentication patterns are detected:

```javascript
// JWT verification
jwt.verify(token, secret);
jsonwebtoken.decode(token);

// Passport.js
passport.authenticate('local');
req.isAuthenticated();

// Session-based
req.session.userId;

// Custom middleware naming
authMiddleware, verifyToken, ensureAuth, protectRoute, guardAdmin

// RBAC patterns
req.user.role === 'admin';
req.user.roles.includes('manager');
```

---

## Configuration

Web-Wreck operates with zero configuration. All analysis is automatic and based on heuristics.

### Ignored Directories

The following directories are automatically excluded from analysis:

```
node_modules, .git, dist, build, coverage, .next, out,
frontend, public, static, assets
```

### Analyzed File Extensions

```
.js, .ts, .jsx, .tsx
```

---

## Troubleshooting

### Common Issues

**"SSL certificate error while cloning"**
- If cloning fails due to self-signed certificates or corporate proxies, run with `--insecure`:
  ```bash
  web-wreck <github-repo-url> --insecure
  ```

**"Failed to clone repository"**
- Ensure the repository URL is a valid, publicly accessible GitHub URL
- Format: `https://github.com/owner/repository`
- Check your internet connection and Git configuration
- Private repositories are not supported in the current version

**No routes detected**
- Web-Wreck only detects Express-style routing (`app.get()`, `router.post()`, etc.)
- Ensure the target project uses Express.js or Express-compatible routing
- Routes using regex patterns or route chaining are not yet supported
- Check that source files are not in an ignored directory

**Parse errors on some files**
- Files that fail to parse are silently skipped with a warning
- Check console output for `[WARN] Skipping <file>` messages
- Common cause: syntax not supported by the Babel parser configuration

**HTML report shows blank graph**
- Ensure you have an internet connection (D3.js is loaded from CDN)
- Try opening the report in a different browser
- Check browser console for JavaScript errors

**Automatic Temp Cleanup**
- Cloned repositories are stored temporarily in `.web-wreck/` and cleaned up automatically in the `finally` block of the pipeline upon completion or error.

---

## Project Scripts

| Command | Description |
|---------|-------------|
| `npm run build` | Compile TypeScript to JavaScript in `dist/` |
| `npm run start` | Run the compiled CLI tool |
| `npm run dev` | Run directly from TypeScript source (development) |

---

## License

MIT
