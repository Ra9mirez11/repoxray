# RepoXray (`rxray`)

[![Web Scanner](https://img.shields.io/badge/Live_Scanner-repoxray.pages.dev-06b6d4?style=flat-square&labelColor=0f172a)](https://repoxray.pages.dev)
[![npm version](https://img.shields.io/npm/v/rxray?style=flat-square&labelColor=0f172a&color=38bdf8)](https://www.npmjs.com/package/rxray)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-10b981?style=flat-square&labelColor=0f172a)](https://www.npmjs.com/package/rxray)
[![RepoXray Security & AI Score](https://img.shields.io/badge/RepoXray-A%2B%20(100%2F100)-10b981?style=flat-square&labelColor=0f172a)](https://repoxray.pages.dev/?repo=Ra9mirez11/repoxray)
[![License: MIT](https://img.shields.io/badge/License-MIT-94a3b8?style=flat-square&labelColor=0f172a)](./LICENSE)

**Catch leaked keys, malware tombstones, OSV vulnerabilities, AI slopsquatting, and LLM context bloat before you push.**

- **Browser App (100% Web Worker, 0 bytes uploaded):** [https://repoxray.pages.dev](https://repoxray.pages.dev)
- **Live Self-Audit Demo:** [https://repoxray.pages.dev/?repo=Ra9mirez11/repoxray](https://repoxray.pages.dev/?repo=Ra9mirez11/repoxray)
- **5-Letter Zero-Dependency CLI:**

```bash
npx rxray .
```

---

## Why RepoXray Exists

Modern development moves fast with AI coding agents, MCP servers, and thousands of open-source packages. Traditional scanners miss the failure modes that break teams today:

1. **AI Slopsquatting & Malware Tombstones (`SC-SLOPSQUATTING-404` / `SC-NPM-SECURITY-TOMBSTONE`):** LLMs frequently hallucinate plausible package names or reference taken-down malicious packages (`0.0.1-security`). RepoXray checks live registry existence, package age (`< 21` days), wrong-registry MCP servers (`uvx` vs `npm`), and lookalike vendor scopes (`@anthropic/*` vs `@anthropic-ai/*`).
2. **Malicious Lifecycle Hooks (`SC-MALICIOUS-LIFECYCLE-HOOK`):** Flags `preinstall` / `postinstall` scripts invoking `curl`, `wget`, `powershell`, `bash -c`, or `eval`.
3. **Known CVEs Across Ecosystems (`SC-OSV-VULNERABILITY`):** Queries Google's `OSV.dev` database in a single batch across `npm` (resolving exact `package-lock.json` versions), `PyPI` (`requirements.txt`), and Rust (`Cargo.toml`).
4. **Secret, `.env` & MCP Config Exposure (`SEC-*`):** Combines high-precision patterns with Shannon entropy filtering, redacts all matched secrets automatically (including inside static code-safety snippets), verifies `.gitignore` / `.aiignore` protection, and audits `.mcp.json` / `claude_desktop_config.json` for plaintext tokens and unpinned `npx -y` execution.
5. **Deterministic AI Guardrails (`AGENTS.md` & `.aiignore`):** Measures exact LLM context token waste (lockfiles, minified bundles, sourcemaps) and compiles project-specific `AGENTS.md`, `.cursorrules`, `.aiignore`, and an XML-sandboxed **Zero-Token AI Fix Prompt** for your existing AI editor.

---

## Quickstart (CLI)

No global installation required. The published `rxray` CLI (`~20 KB`) has **0 runtime dependencies**.

```bash
# 1. Scan current directory
npx rxray .

# 2. Scan any public GitHub repository remotely
npx rxray expressjs/express

# 3. Generate and write .aiignore + AGENTS.md guardrails into your project
npx rxray . --write-shield

# 4. Install fast (<1s) offline Git pre-commit security gate
npx rxray init-hook

# 5. Run offline (air-gapped static + secret + token scan only)
npx rxray . --offline

# 6. Export structured JSON report for compliance / SOC2 / NIS2 pipelines
npx rxray . --json > repoxray-audit.json
```

### CLI Commands & Options

| Command / Flag | Description |
| :--- | :--- |
| `init-hook` | Installs an offline `<1s` Git pre-commit gate in `.git/hooks/pre-commit` |
| `--write-shield` | Generates tailored `.aiignore` and `AGENTS.md` files in the target directory |
| `--force` | Overwrites existing `.aiignore` / `AGENTS.md` / `pre-commit` hook |
| `--ci` | Exits with code `1` if any Critical/High finding is found or score is below `75` |
| `--fail-below <0-100>` | Custom minimum passing score threshold for CI/CD gates |
| `--offline` | Skips live `OSV.dev` and `registry.npmjs.org` network telemetry |
| `--json` | Prints machine-readable JSON audit report to `stdout` |

---

## GitHub Actions CI/CD Gate (1-Line Composite Action)

Block pull requests that introduce leaked credentials, unpinned MCP servers, hallucinated packages, or vulnerable dependencies by adding `.github/workflows/repoxray.yml`:

```yaml
name: RepoXray Security Gate
on: [push, pull_request]

jobs:
  repoxray:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Enforce RepoXray Gate
        uses: Ra9mirez11/repoxray@main
        with:
          fail-below: '85'
```

---

## Privacy & Zero-Upload Guarantee

- **Web App:** File traversal uses the browser's local File System Access / Drag-and-Drop APIs inside a bounded RAM buffer + dedicated Web Worker. Source files are **never** transmitted to any backend server. Enable **Air-Gapped Mode** in the UI for zero outbound registry calls.
- **Secret Redaction & Symlink Safety:** Every detected credential is masked (`sk-pr****...****9a2f`) across terminal output, UI cards, and exported remediation prompts. CLI file writes inspect `lstat` to refuse symbolic-link overwrites and strip terminal escape sequences.
- **Zero Runtime Dependencies:** `package.json` ships with `"dependencies": {}` to keep the scanner hardened against transitive supply-chain attacks.

---

## Community & Security Research Acknowledgments

- Special thanks to **`@X1Y1`** for sharing empirical telemetry from scanning **10,659 public MCP configurations**, directly inspiring RepoXray's `0.0.1-security` malware tombstone detection (`SC-NPM-SECURITY-TOMBSTONE`), wrong-registry `uvx` vs `npm` checks (`SC-MCP-WRONG-REGISTRY`), vendor scope impersonation checks (`SC-SCOPE-IMPERSONATION-RISK`), and array-command MCP config parsing.

---

## Documentation & Contributing

- [Architecture & Rule Reference](./docs/ARCHITECTURE.md)
- [Security Policy](./SECURITY.md)
- [Contributing Guide](./CONTRIBUTING.md)
- [Changelog](./CHANGELOG.md)

## Sponsorship & Legal Notice

RepoXray is MIT-licensed open-source software provided `"AS IS"` without warranty of any kind; automated heuristic scores do not replace manual penetration testing or formal compliance certification. To back ongoing vulnerability signature research or request written supply-chain security audits, visit [GitHub Sponsors](https://github.com/sponsors/Ra9mirez11).
