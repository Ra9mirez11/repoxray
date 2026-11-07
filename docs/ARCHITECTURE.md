# RepoXray Architecture & Rule Reference

## 1. System Overview

RepoXray separates **I/O adapters** from its **pure analysis & compilation core**:

- **`src/core/` (Isomorphic Engine):** Zero-dependency TypeScript operating strictly on in-memory `VirtualFile[]` arrays and standard Web `fetch()`.
- **`src/web/` (Browser Adapter):** Reads local folders via File System Access API / HTML5 Drag-and-Drop in browser RAM or streams public GitHub trees via `raw.githubusercontent.com`.
- **`src/cli/` (Node CLI Adapter):** Bundled via `esbuild` into a single standalone `dist-cli/cli.mjs` executable (`~25 KB`, `0` runtime dependencies).

## 2. Scoring Formula

Each scan computes four category sub-scores starting at `100` with severity deductions (`critical: -28`, `high: -15`, `medium: -7`, `low: -3`):

- **Secrets & Exposure (`35%` weight):** `SEC-AWS-KEY`, `SEC-GITHUB-TOKEN`, `SEC-AI-API-KEY`, `SEC-GOOGLE-API-KEY`, `SEC-STRIPE-LIVE`, `SEC-SLACK-TOKEN`, `SEC-PRIVATE-KEY`, `SEC-DB-CONN-URI`, `SEC-GENERIC-HIGH-ENTROPY`, `SEC-GITIGNORE-ENV`, `SEC-PLAINTEXT-ENV-EXPOSED`, `SEC-MCP-PLAINTEXT-ENV`.
- **Supply-Chain & Slopsquatting (`30%` weight):** `SC-SLOPSQUATTING-404`, `SC-NEWLY-REGISTERED-PKG`, `SC-MALICIOUS-LIFECYCLE-HOOK`, `SC-LIFECYCLE-HOOK`, `SC-DEP-NETWORK-HOOK`, `SC-OSV-VULNERABILITY`, `SC-UNPINNED-SPEC`, `SEC-MCP-UNPINNED-NPX`.
- **Static Code Safety (`20%` weight):** `CODE-DYNAMIC-EVAL`, `CODE-SHELL-INJECTION`, `CODE-SQL-TEMPLATE-INJECTION`, `CODE-TLS-DISABLED`, `CODE-UNSAFE-HTML-SINK`, `CODE-PY-UNSAFE-EXEC`.
- **AI Context Readiness (`15%` weight):** `AI-MISSING-AIIGNORE`, `AI-UNSHIELDED-BLOAT`, `AI-NO-GUARDRAIL-MANIFEST`.

Any `critical` finding caps the composite score at `68` (maximum Grade `C`) until remediated.
