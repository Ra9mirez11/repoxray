# RepoXray

[![npm version](https://img.shields.io/npm/v/repoxray?style=flat-square&labelColor=0f172a&color=38bdf8)](https://www.npmjs.com/package/repoxray)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-10b981?style=flat-square&labelColor=0f172a)](https://www.npmjs.com/package/repoxray)
[![RepoXray Security & AI Score](https://img.shields.io/badge/RepoXray-A%2B%20(100%2F100)-10b981?style=flat-square&labelColor=0f172a)](https://github.com/Ra9mirez11/repoxray)
[![License: MIT](https://img.shields.io/badge/License-MIT-94a3b8?style=flat-square&labelColor=0f172a)](./LICENSE)

**Instant, zero-upload security, supply-chain, AI slopsquatting, secret exposure, and LLM context X-Ray for any codebase.**

Audit any local folder or public GitHub repository in under 2 seconds—either in the **100% client-side Web App** (0 bytes uploaded to any server) or via the **zero-dependency CLI**:

```bash
npx repoxray .
```

---

## Why RepoXray Exists

Modern development moves fast with AI coding agents, MCP servers, and thousands of open-source packages. Traditional scanners miss the failure modes that break teams today:

1. **AI Slopsquatting (`SC-SLOPSQUATTING-404`):** LLMs frequently hallucinate plausible package names. Attackers register those missing names on `npm` to execute code on `npm install`. RepoXray checks live registry existence and package age (`< 21` days) before you get compromised.
2. **Malicious Lifecycle Hooks (`SC-MALICIOUS-LIFECYCLE-HOOK`):** Flags `preinstall` / `postinstall` scripts invoking `curl`, `wget`, `powershell`, `bash -c`, or `eval`.
3. **Known CVEs Across Ecosystems (`SC-OSV-VULNERABILITY`):** Queries Google's `OSV.dev` database in a single batch across `npm` (resolving exact `package-lock.json` versions), `PyPI` (`requirements.txt`), and Rust (`Cargo.toml`).
4. **Secret, `.env` & MCP Config Exposure (`SEC-*`):** Combines high-precision patterns with Shannon entropy filtering, redacts all matched secrets automatically, verifies `.gitignore` / `.aiignore` protection, and audits `.mcp.json` / `claude_desktop_config.json` for plaintext tokens and unpinned `npx -y` execution.
5. **Deterministic AI Guardrails (`AGENTS.md` & `.aiignore`):** Measures exact LLM context token waste (lockfiles, minified bundles, sourcemaps) and compiles project-specific `AGENTS.md`, `.cursorrules`, `.aiignore`, and a **Zero-Token AI Fix Prompt** for your existing AI editor.

---

## Quickstart (CLI)

No global installation required. The published `repoxray` CLI has **0 runtime dependencies**.

```bash
# 1. Scan current directory
npx repoxray .

# 2. Scan any public GitHub repository remotely
npx repoxray expressjs/express

# 3. Generate and write .aiignore + AGENTS.md guardrails into your project
npx repoxray . --write-shield

# 4. Run offline (air-gapped static + secret + token scan only)
npx repoxray . --offline

# 5. Export structured JSON report for compliance / SOC2 / NIS2 pipelines
npx repoxray . --json > repoxray-audit.json
```

### CLI Options

| Flag | Description |
| :--- | :--- |
| `--write-shield` | Generates tailored `.aiignore` and `AGENTS.md` files in the target directory |
| `--force` | Overwrites existing `.aiignore` / `AGENTS.md` when paired with `--write-shield` |
| `--ci` | Exits with code `1` if any Critical/High finding is found or score is below `75` |
| `--fail-below <0-100>` | Custom minimum passing score threshold for CI/CD gates |
| `--offline` | Skips live `OSV.dev` and `registry.npmjs.org` network telemetry |
| `--json` | Prints machine-readable JSON audit report to `stdout` |

---

## GitHub Actions CI/CD Gate

Block pull requests that introduce leaked credentials, unpinned MCP servers, hallucinated packages, or vulnerable dependencies by adding `.github/workflows/repoxray.yml`:

```yaml
name: RepoXray Security Gate
on: [push, pull_request]

jobs:
  repoxray:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - name: Enforce RepoXray Gate
        run: npx repoxray . --ci --fail-below 85
```

---

## Privacy & Zero-Upload Guarantee

- **Web App:** File traversal uses the browser's local File System Access / Drag-and-Drop APIs directly in client RAM. Source files are **never** transmitted to any backend server.
- **Secret Redaction:** Every detected credential is immediately masked (`sk-pr****...****9a2f`) in terminal output, UI cards, and exported remediation prompts.
- **Zero Runtime Dependencies:** `package.json` ships with `"dependencies": {}` to keep the scanner itself hardened against transitive supply-chain attacks.

---

## Documentation & Contributing

- [Architecture & Rule Reference](./docs/ARCHITECTURE.md)
- [Security Policy](./SECURITY.md)
- [Contributing Guide](./CONTRIBUTING.md)
- [Changelog](./CHANGELOG.md)

## Sponsorship & Support

RepoXray is MIT-licensed open-source software. If RepoXray protects your engineering team or saves your CI/CD pipeline from a supply-chain incident, consider backing ongoing signature and rule development via [GitHub Sponsors](https://github.com/sponsors/Ra9mirez11).
