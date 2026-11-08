import { isMcpConfigPath, parseMcpConfigContent } from './mcpParser';
import type { Finding, Severity, VirtualFile } from './types';

interface SecretRule {
  ruleId: string;
  title: string;
  severity: Severity;
  pattern: RegExp;
  minEntropy?: number;
  remediation: string;
}

const LOCKFILE_NAMES = new Set([
  'package-lock.json',
  'pnpm-lock.yaml',
  'yarn.lock',
  'bun.lock',
  'bun.lockb',
  'Cargo.lock',
  'poetry.lock',
  'uv.lock',
  'composer.lock',
]);

const PLACEHOLDER_HINTS = [
  'example',
  'your_',
  'your-',
  'changeme',
  'placeholder',
  'dummy',
  'sample',
  'xxxx',
  '0000000000',
  'replace_me',
  '<your',
  'insert_',
  'todo_',
  'process.env',
  'os.environ',
  'import.meta.env',
];

const SENSITIVE_MCP_ENV_KEY_RE =
  /(?:key|token|secret|password|passwd|pwd|auth|pat|credential|bearer|cookie|session|dsn|conn|webhook|private|cert|jwt)/i;

const NON_SECRET_TOKEN_COUNT_KEY_RE =
  /^(?:max_?tokens?|min_?tokens?|token_?limit|context_?tokens?|output_?tokens?|public_?url)$/i;

const BENIGN_ENUM_ENV_VAL_RE =
  /^(?:true|false|yes|no|development|production|staging|local|test|testing|debug|info|warn|warning|error|trace|silent|utf-?8|ascii|json|text|stdio|sse|http|https|localhost)$/i;

export function calculateEntropy(input: string): number {
  if (!input || input.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of input) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  const len = input.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function redactSecret(raw: string): string {
  const trimmed = raw.trim();
  if (trimmed.length <= 10) {
    return trimmed.slice(0, 2) + '****';
  }
  return `${trimmed.slice(0, 5)}****...****${trimmed.slice(-4)}`;
}

function isLikelyPlaceholder(value: string): boolean {
  const lower = value.toLowerCase();
  if (/^<[^>]+>$/.test(lower)) return true;
  return PLACEHOLDER_HINTS.some((hint) => lower.includes(hint));
}

function isDynamicSecretReference(value: string): boolean {
  const v = value.trim();
  if (!v) return true;
  if (v.startsWith('${') || /^\$[A-Za-z_][A-Za-z0-9_]*$/.test(v)) return true;
  if (/^%[A-Za-z_][A-Za-z0-9_]*%$/.test(v)) return true;
  if (/^\{\{\s*[A-Za-z0-9_.:-]+\s*\}\}$/.test(v)) return true;
  if (/^(?:op|vault|aws-ssm|gcp-sm|azure-kv|keychain):\/\//i.test(v)) return true;
  return false;
}

function isPlainFilesystemPathOrPublicUrl(value: string): boolean {
  const v = value.trim();
  if (
    v.startsWith('/') ||
    v.startsWith('./') ||
    v.startsWith('../') ||
    v.startsWith('~/') ||
    /^[A-Za-z]:[/\\]/.test(v)
  ) {
    return true;
  }

  if (/^https?:\/\//i.test(v)) {
    // Embedded user:pass@ credentials or webhook endpoints ARE sensitive
    const hasEmbeddedCreds = /^https?:\/\/[^/\s:@]+:[^/\s@]+@/i.test(v);
    const isWebhookUrl = /(?:hooks\.slack\.com|discord(?:app)?\.com\/api\/webhooks|webhook)/i.test(
      v,
    );
    return !hasEmbeddedCreds && !isWebhookUrl;
  }

  return false;
}

const SECRET_RULES: SecretRule[] = [
  {
    ruleId: 'SEC-AWS-KEY',
    title: 'Hardcoded AWS Access Key ID',
    severity: 'critical',
    pattern: new RegExp('\\b(A3T[A-Z0-9]|AKIA|ASIA|AGPA|AIDA)[A-Z0-9]{16}\\b'),
    remediation:
      'Revoke the IAM key immediately in AWS Console and load credentials via IAM roles or environment variables.',
  },
  {
    ruleId: 'SEC-GITHUB-TOKEN',
    title: 'Hardcoded GitHub Personal Access Token',
    severity: 'critical',
    pattern: new RegExp('\\b(gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\\b'),
    remediation:
      'Revoke the token in GitHub Developer Settings and inject it via GitHub Actions Secrets or local OS environment.',
  },
  {
    ruleId: 'SEC-AI-API-KEY',
    title: 'Hardcoded AI Provider API Key (OpenAI / Anthropic / Perplexity / HuggingFace)',
    severity: 'critical',
    pattern: new RegExp(
      '\\b(sk-(?:proj-|ant-api03-)?[A-Za-z0-9_-]{28,200}|pplx-[A-Za-z0-9]{32,128}|hf_[A-Za-z0-9]{30,128})\\b',
    ),
    minEntropy: 3.6,
    remediation:
      'Rotate the API key in your provider dashboard and reference it exclusively via server-side environment variables.',
  },
  {
    ruleId: 'SEC-SAAS-MCP-TOKEN',
    title: 'Hardcoded SaaS / MCP Service Token (Notion / Linear / Tavily / GitLab / Figma / npm)',
    severity: 'critical',
    pattern: new RegExp(
      '\\b(ntn_[A-Za-z0-9]{30,120}|lin_api_[A-Za-z0-9]{28,120}|tvly-[A-Za-z0-9_-]{24,120}|fc-[a-f0-9]{28,64}|glpat-[A-Za-z0-9_-]{20,100}|figd_[A-Za-z0-9_-]{28,120}|sbp_[a-f0-9]{32,80}|npm_[A-Za-z0-9]{32,80})\\b',
    ),
    minEntropy: 3.5,
    remediation:
      'Revoke the exposed service token in the vendor dashboard and inject it at runtime via OS environment variables.',
  },
  {
    ruleId: 'SEC-GOOGLE-API-KEY',
    title: 'Hardcoded Google Cloud / Gemini API Key',
    severity: 'high',
    pattern: new RegExp('\\b(AIza[0-9A-Za-z_-]{35})\\b'),
    remediation:
      'Restrict or rotate the key in Google Cloud Console and move it into environment configuration.',
  },
  {
    ruleId: 'SEC-STRIPE-LIVE',
    title: 'Hardcoded Stripe Live Secret Key',
    severity: 'critical',
    pattern: new RegExp('\\b((?:sk|rk)_live_[0-9a-zA-Z]{24,99})\\b'),
    remediation:
      'Roll the live Stripe secret key immediately in Stripe Dashboard and load via secure server secrets.',
  },
  {
    ruleId: 'SEC-SLACK-TOKEN',
    title: 'Hardcoded Slack Token or Webhook',
    severity: 'high',
    pattern: new RegExp(
      '(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*|https://hooks\\.slack\\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)',
    ),
    remediation:
      'Invalidate the Slack token/webhook and store webhook URLs in runtime environment variables.',
  },
  {
    ruleId: 'SEC-PRIVATE-KEY',
    title: 'Embedded Cryptographic Private Key',
    severity: 'critical',
    pattern: new RegExp('-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----'),
    remediation:
      'Remove the private key file from version control, rotate the keypair, and add *.pem / *.key to .gitignore and .aiignore.',
  },
  {
    ruleId: 'SEC-DB-CONN-URI',
    title: 'Database Connection URI With Embedded Credentials',
    severity: 'critical',
    pattern: new RegExp(
      '\\b((?:postgres(?:ql)?|mongodb(?:\\+srv)?|mysql|redis|rediss|amqp)://[^:\\s"\'<>]+:[^@\\s"\'<>]{4,}@[^\\s"\'<>]+)',
      'i',
    ),
    remediation:
      'Move the connection string to DATABASE_URL in a non-committed runtime secret store and rotate the DB password.',
  },
  {
    ruleId: 'SEC-GENERIC-HIGH-ENTROPY',
    title: 'High-Entropy Secret Assigned in Source Code',
    severity: 'high',
    pattern: new RegExp(
      '(?:api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token|private[_-]?key|client[_-]?secret|jwt[_-]?secret)\\s*[:=]\\s*["\']([A-Za-z0-9+/=_-]{24,128})["\']',
      'i',
    ),
    minEntropy: 3.85,
    remediation:
      'Replace hardcoded secret string literal with process.env.<VARIABLE_NAME> or equivalent runtime secret injection.',
  },
];

function matchesKnownSecretSignature(value: string): boolean {
  for (const rule of SECRET_RULES) {
    if (rule.ruleId === 'SEC-GENERIC-HIGH-ENTROPY') continue;
    const m = rule.pattern.exec(value);
    if (!m) continue;
    const candidate = rule.ruleId === 'SEC-AWS-KEY' ? m[0] : (m[1] ?? m[0]);
    if (isLikelyPlaceholder(candidate)) continue;
    if (rule.minEntropy !== undefined && calculateEntropy(candidate) < rule.minEntropy) continue;
    return true;
  }
  return false;
}

function shouldFlagMcpEnvEntry(envKey: string, rawVal: string): boolean {
  const val = rawVal.trim();
  if (val.length < 8) return false;
  if (isDynamicSecretReference(val) || isLikelyPlaceholder(val)) return false;
  if (BENIGN_ENUM_ENV_VAL_RE.test(val) || /^\d+(?:\.\d+)?$/.test(val)) return false;

  // 1. Known provider token / DB URI / private key prefix in value -> always flag regardless of key name
  if (matchesKnownSecretSignature(val)) return true;

  // 2. Skip non-secret local paths and public base URLs
  if (isPlainFilesystemPathOrPublicUrl(val)) return false;

  // 3. Sensitive credential key name (`*_API_KEY`, `*_TOKEN`, `*_SECRET`, `*_PASSWORD`, etc.)
  if (SENSITIVE_MCP_ENV_KEY_RE.test(envKey) && !NON_SECRET_TOKEN_COUNT_KEY_RE.test(envKey)) {
    return true;
  }

  // 4. Arbitrary env key name holding a high-entropy single-token secret (e.g. `"BRAVE": "BSA..."`)
  if (!/\s/.test(val) && val.length >= 20 && calculateEntropy(val) >= 3.85) {
    return true;
  }

  return false;
}

/**
 * Redacts any inline secret tokens matched by SECRET_RULES inside an arbitrary code snippet
 * so static code-safety evidence lines never leak live credentials into UI or AI prompts.
 */
export function redactInlineSecrets(line: string): string {
  if (!line || line.length > 1500) return line;
  let output = line;

  for (const rule of SECRET_RULES) {
    const flags = rule.pattern.flags.includes('g') ? rule.pattern.flags : `${rule.pattern.flags}g`;
    const globalRegex = new RegExp(rule.pattern.source, flags);
    output = output.replace(globalRegex, (...args) => {
      const fullMatch = args[0] as string;
      const group1 = typeof args[1] === 'string' ? (args[1] as string) : undefined;
      const candidate =
        rule.ruleId === 'SEC-AWS-KEY' ? fullMatch : (group1 ?? fullMatch);

      if (isLikelyPlaceholder(candidate)) return fullMatch;
      if (rule.minEntropy !== undefined && calculateEntropy(candidate) < rule.minEntropy) {
        return fullMatch;
      }

      if (candidate !== fullMatch && fullMatch.includes(candidate)) {
        return fullMatch.replace(candidate, redactSecret(candidate));
      }
      return redactSecret(fullMatch);
    });
  }

  return output;
}

function isEnvFile(path: string): boolean {
  const base = path.split('/').pop() ?? path;
  if (!base.startsWith('.env')) return false;
  const safeTemplates = ['.env.example', '.env.sample', '.env.template', '.env.dist'];
  return !safeTemplates.includes(base.toLowerCase());
}

export function scanSecretsAndExposure(files: VirtualFile[]): Finding[] {
  const findings: Finding[] = [];
  let seq = 1;

  const isRepoXraySelfScan =
    files.some((f) => f.path === 'src/core/mcpParser.ts') &&
    files.some((f) => f.path === 'src/core/supplyChain.ts');

  const gitignoreFile = files.find((f) => f.path === '.gitignore');
  const aiIgnoreFile = files.find(
    (f) => f.path === '.aiignore' || f.path === '.cursorignore' || f.path === '.claudeignore',
  );

  // 1. Check .gitignore secret hygiene
  if (!gitignoreFile) {
    findings.push({
      id: `sec-${seq++}`,
      ruleId: 'SEC-NO-GITIGNORE',
      category: 'secrets',
      severity: 'medium',
      title: 'Missing .gitignore File',
      description:
        'Repository has no root .gitignore file, creating high risk of committing .env files, keys, and build artifacts.',
      file: '.gitignore',
      remediation: 'Add a strict .gitignore covering .env*, *.pem, *.key, and build directories.',
    });
  } else {
    const gi = gitignoreFile.content;
    const coversEnv = /(^|\n)\s*\.env(\*|\.\*|\s|$)/m.test(gi);
    if (!coversEnv) {
      findings.push({
        id: `sec-${seq++}`,
        ruleId: 'SEC-GITIGNORE-ENV',
        category: 'secrets',
        severity: 'high',
        title: '.env Files Not Ignored in .gitignore',
        description:
          'Root .gitignore does not exclude .env / .env.* files. Local secrets can be accidentally staged and pushed.',
        file: '.gitignore',
        remediation: 'Append `.env` and `.env.*` (with `!.env.example`) to .gitignore.',
      });
    }
  }

  // 2. Scan individual files
  for (const file of files) {
    const baseName = file.path.split('/').pop() ?? file.path;
    if (LOCKFILE_NAMES.has(baseName)) continue;

    // Skip RepoXray's own signature definitions when dogfooding
    if (isRepoXraySelfScan && file.path === 'src/core/secretScanner.ts') continue;

    // 2a. Check live .env files present in workspace
    if (isEnvFile(file.path)) {
      const lines = file.content.split(/\r?\n/);
      let populatedSecretCount = 0;
      let firstSecretLine = 1;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line || line.startsWith('#')) continue;
        const eqIdx = line.indexOf('=');
        if (eqIdx > 0) {
          const val = line.slice(eqIdx + 1).trim().replace(/^['"]|['"]$/g, '');
          if (val.length >= 8 && !isLikelyPlaceholder(val) && !isDynamicSecretReference(val)) {
            if (populatedSecretCount === 0) firstSecretLine = i + 1;
            populatedSecretCount++;
          }
        }
      }

      const aiCoversEnv =
        aiIgnoreFile && /(^|\n)\s*\.env(\*|\.\*|\s|$)/m.test(aiIgnoreFile.content);

      findings.push({
        id: `sec-${seq++}`,
        ruleId: 'SEC-PLAINTEXT-ENV-EXPOSED',
        category: 'secrets',
        severity: populatedSecretCount > 0 ? 'high' : 'medium',
        title: `Plaintext ${baseName} Exposed to Workspace & AI Agents`,
        description:
          populatedSecretCount > 0
            ? `${baseName} contains ${populatedSecretCount} populated secret value(s)${
                aiCoversEnv
                  ? '.'
                  : ' and is readable by AI coding agents / MCP tools without .aiignore protection.'
              }`
            : `${baseName} exists in workspace without .aiignore isolation.`,
        file: file.path,
        line: firstSecretLine,
        remediation:
          'Exclude .env* in both .gitignore and .aiignore / .cursorignore so LLM agents never ingest live credentials into prompt context.',
      });
    }

    // Track literals already reported by structured MCP `env` inspection to prevent duplicate alerts on the same line
    const reportedMcpEnvLiterals = new Set<string>();

    // 2b. Check MCP server config security (.mcp.json, claude_desktop_config.json, mcp_config.json, etc.)
    if (isMcpConfigPath(file.path)) {
      const mcpServers = parseMcpConfigContent(file.content);
      for (const srv of mcpServers) {
        if (srv.extractedPackage?.isUnpinnedAutoInstall && srv.extractedPackage.ecosystem === 'npm') {
          findings.push({
            id: `sec-${seq++}`,
            ruleId: 'SEC-MCP-UNPINNED-NPX',
            category: 'supply-chain',
            severity: 'high',
            title: `Unpinned '${srv.runner}' Auto-Install in MCP Server "${srv.serverName}"`,
            description:
              'Auto-installing latest unpinned npm package inside MCP configuration executes arbitrary remote code on every IDE startup.',
            file: file.path,
            evidence: srv.rawCommandDisplay,
            remediation:
              'Pin the exact verified package version (e.g. `pkg@1.2.3`) or install locally with lockfile verification.',
          });
        }

        for (const [envKey, strVal] of Object.entries(srv.env)) {
          if (shouldFlagMcpEnvEntry(envKey, strVal)) {
            reportedMcpEnvLiterals.add(strVal.trim());
            const safeEnvKey = envKey.replace(/[^A-Za-z0-9_]/g, '_').slice(0, 64);
            findings.push({
              id: `sec-${seq++}`,
              ruleId: 'SEC-MCP-PLAINTEXT-ENV',
              category: 'secrets',
              severity: 'critical',
              title: `Plaintext Credential "${safeEnvKey}" in MCP Config (${srv.serverName})`,
              description:
                'MCP configuration stores a literal credential inside its `env` block (or CLI `-e` flag) instead of an environment variable reference.',
              file: file.path,
              evidence: `${safeEnvKey}=${redactSecret(strVal)}`,
              remediation: `Replace literal value with "\${${safeEnvKey}}" (or "\${env:${safeEnvKey}}") and inject from OS secret store.`,
            });
          }
        }
      }
    }

    // 2c. Scan source lines with high-precision secret rules
    const lines = file.content.split(/\r?\n/);
    for (let idx = 0; idx < lines.length; idx++) {
      const line = lines[idx];
      if (line.length > 1500) continue; // Skip minified single-line blobs
      if (line.includes('sha512-') || line.includes('sha256-')) continue;

      for (const rule of SECRET_RULES) {
        const match = rule.pattern.exec(line);
        if (!match) continue;

        const candidate =
          rule.ruleId === 'SEC-AWS-KEY' ? match[0] : (match[1] ?? match[0]);
        if (isLikelyPlaceholder(candidate)) continue;
        if (reportedMcpEnvLiterals.has(candidate) || Array.from(reportedMcpEnvLiterals).some((lit) => lit.includes(candidate))) {
          continue;
        }

        if (rule.minEntropy !== undefined) {
          const ent = calculateEntropy(candidate);
          if (ent < rule.minEntropy) continue;
        }

        findings.push({
          id: `sec-${seq++}`,
          ruleId: rule.ruleId,
          category: 'secrets',
          severity: rule.severity,
          title: rule.title,
          description: `Detected exposed credential pattern (${rule.ruleId}) in file "${file.path}".`,
          file: file.path,
          line: idx + 1,
          evidence: redactSecret(candidate),
          remediation: rule.remediation,
        });
        break; // Avoid duplicate alerts on the exact same line
      }
    }
  }

  return findings;
}
