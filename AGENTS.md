# AGENTS.md — Architectural & Security Guardrails (RepoXray)

> Enforced by **RepoXray** (`npx repoxray . --ci`).

## 1. Architecture Boundaries
- `src/core/` MUST remain 100% isomorphic TypeScript with zero Node-only or DOM-only dependencies so it executes identically in Browser Web Workers and Node CLI.
- `package.json` MUST keep `"dependencies": {}` empty so the published `npx repoxray` CLI stays dependency-free and immune to transitive supply-chain attacks.

## 2. Security Rules
- Never place literal API keys, tokens, or credentials in source code, demo presets, or unit tests. Assemble synthetic test fixtures dynamically at runtime.
- Never use `dangerouslySetInnerHTML`, `eval()`, `new Function()`, or shell string interpolation.
- Run `npm test && npm run build && npm run xray` before every release.
