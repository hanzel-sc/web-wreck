# Web-Wreck Setup Guide

## Prerequisites

- **Node.js** v18+ installed
- **Git** installed and configured
- **npm** (comes with Node.js)

## Installation

```bash
# Navigate to the backend directory
cd c:\Users\chris\OneDrive\Desktop\fun-projects\web-wreck\backend

# Install dependencies
npm install

# Build the TypeScript project
npm run build
```

## Usage

Run the analyzer on any public GitHub repository:

```bash
# Basic usage
node dist/index.js <github-repo-url>

# Example
node dist/index.js https://github.com/hanzel-sc/iwp-placement-portal
```

## Output

The tool generates reports in the `web-wreck-output` directory:

| File | Description |
|------|-------------|
| `report-YYYY-MM-DD-XXXX.html` | Interactive HTML visualization with D3.js tree graph |
| `report-YYYY-MM-DD-XXXX.md` | Markdown summary of findings |

## Understanding the Report

### Visualization Legend

| Color | Meaning |
|-------|---------|
| 🔴 Red | Vulnerable route - missing authentication |
| 🟢 Green | Protected route - has auth middleware |
| 🔵 Blue | Public route - intentionally no auth (login, register, etc.) |
| 🟡 Yellow | Auth middleware node |
| ⚪ Gray | Handler node |
| 🔵 Dark Blue | Application entry point |

### Finding Severity

- **Critical**: Privileged routes with no authentication
- **High**: Routes with conditional or weak authentication
- **Medium**: Regular routes missing authentication
- **Info**: Intentionally public endpoints (no action needed)

## Troubleshooting

**PowerShell script execution disabled?**
Use cmd instead:
```bash
cmd /c "npm run build"
cmd /c "node dist/index.js <repo-url>"
```

**Repository not found?**
Ensure the GitHub repository URL is:
- Publicly accessible
- Valid and exists
- In format: `https://github.com/owner/repo`
