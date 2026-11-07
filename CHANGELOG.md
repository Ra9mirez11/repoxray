# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-08

### Added
- Isomorphic TypeScript scanning engine (`src/core/`) shared across Browser Web UI and zero-dependency `npx repoxray` CLI.
- Supply-chain & slopsquatting module querying `OSV.dev` batch API (`npm`, `PyPI`, `crates.io`) and `registry.npmjs.org` for unregistered `404` packages, newly created packages (`<= 21` days), and risky `postinstall` hooks.
- Exact locked version resolution from `package-lock.json`.
- High-precision secret scanner with Shannon entropy filtering, automatic secret redaction, `.gitignore` hygiene checks, and `.mcp.json` / `claude_desktop_config.json` security auditing.
- LLM token footprint analyzer and deterministic guardrail compiler generating `AGENTS.md`, `.cursorrules`, `.aiignore`, SVG score badges, and Zero-Token AI Fix Prompts.
- Zero-upload React + Tailwind CSS v4 cyber-diagnostic Web UI with local directory picker, drag-and-drop folder traversal, public GitHub URL scanner, and 1-click live demo.
