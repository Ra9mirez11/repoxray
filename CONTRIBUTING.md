# Contributing to RepoXray

Contributions that add high-signal detection rules, improve parser coverage, or reduce false positives are welcome.

## Development Setup

Requirements: Node.js `>= 20.0.0` and `npm`.

```bash
git clone https://github.com/Ra9mirez11/repoxray.git
cd repoxray
npm install
npm test
npm run dev
```

## Core Design Constraints

1. **Isomorphic Core (`src/core/`):** Never import `node:fs`, `node:path`, or browser-only `window`/`document` globals inside `src/core/`. All core modules must accept `VirtualFile[]` and run identically in Web Workers and Node.js.
2. **Zero Runtime Dependencies:** Keep `"dependencies": {}` empty in `package.json`.
3. **No Literal Test Secrets:** Assemble synthetic tokens in tests dynamically at runtime (e.g. `['AKIA', 'EXAMPLE...'].join('')`) so secret scanners never trigger false alarms on repository source files.
4. **Self-Audit Gate:** Every pull request must pass `npm test`, `npm run build`, and score **Grade A+ (100/100)** when running `node dist-cli/cli.mjs . --ci --fail-below 95`.
