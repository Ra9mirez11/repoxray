# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- Isomorphic TypeScript scanning engine (`src/core/`) shared across Browser Web UI and zero-dependency `npx repoxray` CLI.
- Supply-chain & slopsquatting module querying `OSV.dev` batch API (`npm`, `PyPI`, `crates.io`) and `registry.npmjs.org` for unregistered `404` packages, newly created packages (`<= 21` days), and risky `postinstall` hooks.
- Exact locked version resolution from `package-lock.json`.
- High-precision secret scanner with Shannon entropy filtering, automatic secret redaction, `.gitignore` hygiene checks, and `.mcp.json` / `claude_desktop_config.json` security auditing.
- LLM token footprint analyzer and deterministic guardrail compiler generating `AGENTS.md`, `.cursorrules`, `.aiignore`, SVG score badges, and Zero-Token AI Fix Prompts.
- Zero-upload React + Tailwind CSS v4 cyber-diagnostic Web UI with local directory picker, drag-and-drop folder traversal, public GitHub URL scanner, and 1-click live demo.
