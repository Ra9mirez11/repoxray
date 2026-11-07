# Security Policy

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `0.1.x` | Yes |

## Security Architecture Commitments

1. **Zero Server-Side Code Ingestion:** RepoXray's web application runs all file parsing and secret scanning strictly inside the user's browser memory.
2. **Zero Runtime Dependencies:** The published `repoxray` npm CLI bundle has zero third-party runtime dependencies (`"dependencies": {}`), minimizing transitive supply-chain surface.
3. **Mandatory Secret Redaction:** Matched credentials are redacted prior to rendering in terminal logs, browser DOM, or generated AI fix prompts.

## Reporting a Vulnerability

Do **not** open a public GitHub issue for undisclosed security vulnerabilities in RepoXray itself.

Please report security issues privately via **GitHub Private Vulnerability Reporting** on the [Security Advisories tab](https://github.com/Ra9mirez11/repoxray/security/advisories/new). You will receive an acknowledgment within 48 hours.
