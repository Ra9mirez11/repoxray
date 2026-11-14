# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.3] - 2026-11-14

### Added
- **GitHub PR / Issue Markdown Scorecard & Automatic `$GITHUB_STEP_SUMMARY` (`compiler.ts`, `cli/index.ts`):** Added `npx rxray . --markdown` and automatic GitHub Actions Job Summary output (`$GITHUB_STEP_SUMMARY`) rendering a full 4-pillar Markdown table and clickable RepoXray score badge on every CI run.
- **1-Click Viral Share Strip & MCP Preset (`App.tsx`):** Added `Copy PR / Issue Report`, `Copy Badge`, and `Share on X` quick-action buttons directly to the main scan results bar, plus `modelcontextprotocol/servers` in the instant GitHub presets.

## [0.3.2] - 2026-11-08

### Added
- **Unpinned Git Install Detection in MCP & Manifests (`SC-MCP-UNPINNED-GIT` / `SC-UNPINNED-GIT-SPEC`):** Detects `npx github:owner/repo`, npm bare `owner/repo` shorthand, `npx git+https://...`, and `uvx --from git+https://...` (plus `package.json` and `requirements.txt` Git URLs) lacking an immutable 40/64-character commit SHA, while preventing Git specifiers from being falsely queried against npm/PyPI registries. *(Thanks again to @X1Y1 for follow-up telemetry from 10,659 public MCP configs).*
- **Expanded MCP `env` Credential & SaaS Token Precision (`SEC-MCP-PLAINTEXT-ENV` / `SEC-SAAS-MCP-TOKEN`):** Added support for `mcp_config.json`, `cline_mcp_settings.json`, `roo_mcp_settings.json`, `.zed/settings.json`, Docker/CLI `-e KEY=VAL` args, and Notion/Linear/Tavily/Firecrawl/Perplexity/HuggingFace/Figma/GitLab/Supabase tokens, while eliminating false positives on benign `env` settings (`NODE_ENV`, paths, public URLs, `MAX_TOKENS`, `op://` / `${env:...}` references) and deduplicating same-line alerts.

## [0.3.1] - 2026-11-08

### Changed
- **Unified Brand & Marketplace Action Identity (`logo.svg`, `favicon.svg`, `og-card.svg`, `action.yml`):** Replaced generic shield iconography across the Web UI, favicon, OpenGraph card, README, and GitHub Action metadata (`crosshair` / `green`) with the RepoXray X-Ray reticle emblem.
- **GitHub Community Standards (`CODE_OF_CONDUCT.md`, `ACCESSIBILITY.md`, `.github/ISSUE_TEMPLATE/*`):** Added complete community health documentation, structured YAML issue forms, and PR checklist.

### Fixed
- **Outage-Proof Fastly Raw CDN Failover (`githubFetcher.ts`):** Added automatic `2.8s` timeout and seamless failover from `api.github.com` to `raw.githubusercontent.com` so remote repository scans remain operational during GitHub REST API `503`/`504` outages.

## [0.3.0] - 2026-11-08

### Added
- **Off-Main-Thread Web Worker (`scan.worker.ts` & `workerClient.ts`):** Browser scanning now executes inside an isolated Web Worker with automatic main-thread fallback so UI rendering stays at 60fps.
- **Air-Gapped Browser Mode & Session GitHub Cache:** Added 1-click Air-Gapped toggle in the Web UI (zero outbound registry queries) and a 5-minute `sessionStorage` cache for public GitHub repository scans.
- **Git Pre-Commit Security Gate (`npx rxray init-hook`):** Installs an offline `<1s` `.git/hooks/pre-commit` hook that blocks commits introducing leaked credentials, unsafe execution sinks, or MCP risks.
- **Official Composite GitHub Action (`action.yml`):** Enables 1-line CI/CD integration via `uses: Ra9mirez11/repoxray@main` and GitHub Marketplace listing.
- **Hardened HTTP Security Headers & GEO Discovery (`public/_headers`, `llms.txt`, `sitemap.xml`, `og-card.svg`):** Added strict `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Permissions-Policy`, OpenGraph/Twitter social cards, JSON-LD `SoftwareApplication` schema, and `llms.txt`.
- **Aceternity / Linear Bento UI Upgrade:** Upgraded Web UI with radial spotlights, architectural grid backdrop, glassmorphic Bento panels, mobile-first Instant Demo CTA ordering, and a dedicated Community Security Research Contributor card honoring `@X1Y1`.

### Security
- **Indirect Prompt Injection & `.aiignore` Negation Hardening (`compiler.ts`):** Wrapped untrusted findings inside `<untrusted_findings_data>` with strict control-character/delimiter sanitization and escaped leading `!` paths in `.aiignore`.
- **Inline Secret Redaction in SAST Evidence (`secretScanner.ts` & `contextAnalyzer.ts`):** Code-safety evidence lines now pass through `redactInlineSecrets` before display or export.
- **External `tests/` Scanning & Symlink/ANSI Hardening (`contextAnalyzer.ts` & `cli/index.ts`):** External repositories' `tests/` folders are now audited for unsafe execution sinks; CLI strips terminal escape sequences and refuses to write through symbolic links (`lstat`).
- **Bounded Browser RAM Reader (`folderReader.ts`):** Enforced file-count (`4,500`) and RAM text buffer (`25 MB`) caps while preserving exact byte telemetry for oversized files.

## [0.2.0] - 2026-11-08

### Added
- **MCP Dependency Extraction & Array Command Parser (`mcpParser.ts`):** Supports `command` as both string and string array (`["npx", "-y", ...]`) in `.mcp.json` / `claude_desktop_config.json` and feeds referenced `npx` / `bunx` / `uvx` packages into live supply-chain telemetry.
- **Malware Tombstone Rule (`SC-NPM-SECURITY-TOMBSTONE`):** Flags `0.0.1-security` / `"security holding package"` placeholders (e.g. removed malicious `mcp-server-*` packages) distinctly from normal 404s or CVEs.
- **Wrong-Registry MCP Rule (`SC-MCP-WRONG-REGISTRY`):** Detects Python `uvx`-only official MCP reference servers (`fetch`, `git`, `sqlite`, `time`, `sentry`) mistakenly called via `npm` (`@modelcontextprotocol/server-*` or unscoped `mcp-server-*`).
- **Vendor Scope Impersonation & Ownership Differentiation (`SC-SCOPE-IMPERSONATION-RISK` / `SC-HALLUCINATED-VENDOR-PKG`):** Flags non-vendor lookalike scopes (such as `@anthropic/*` vs official `@anthropic-ai/*` or `@mcp/*` vs `@modelcontextprotocol/*`) and separates verified vendor-org 404s from open takeover-ready 404s. *(Thanks to @X1Y1 for sharing empirical telemetry from 10,659 public MCP configs).*

## [0.1.1] - 2026-11-08

### Added
- Linked live client-side web portal (`https://repoxray.pages.dev`) in package metadata, README badges, and deep-linked `?repo=owner/repo` viral badges.
- Configured passwordless OIDC Trusted Publishing with cryptographic npm provenance.

## [0.1.0] - 2026-11-08

### Added
- Isomorphic TypeScript scanning engine (`src/core/`) shared across Browser Web UI and zero-dependency `npx rxray` CLI.
- Supply-chain & slopsquatting module querying `OSV.dev` batch API (`npm`, `PyPI`, `crates.io`) and `registry.npmjs.org` for unregistered `404` packages, newly created packages (`<= 21` days), and risky `postinstall` hooks.
- Exact locked version resolution from `package-lock.json`.
- High-precision secret scanner with Shannon entropy filtering, automatic secret redaction, `.gitignore` hygiene checks, and `.mcp.json` / `claude_desktop_config.json` security auditing.
- LLM token footprint analyzer and deterministic guardrail compiler generating `AGENTS.md`, `.cursorrules`, `.aiignore`, SVG score badges, and Zero-Token AI Fix Prompts.
- Zero-upload React + Tailwind CSS v4 cyber-diagnostic Web UI with local directory picker, drag-and-drop folder traversal, public GitHub URL scanner, and 1-click live demo.
