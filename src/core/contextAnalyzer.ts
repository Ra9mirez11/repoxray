import type {
  DetectedStack,
  Finding,
  Severity,
  TokenFileStat,
  VirtualFile,
} from './types';

interface CodeSafetyRule {
  ruleId: string;
  title: string;
  severity: Severity;
  extensions: string[];
  pattern: RegExp;
  description: string;
  remediation: string;
}

const BLOAT_FILE_NAMES = new Set([
  'package-lock.json',
  'pnpm-lock.yaml',
  'yarn.lock',
  'Cargo.lock',
  'poetry.lock',
  'uv.lock',
  'composer.lock',
]);

const CODE_SAFETY_RULES: CodeSafetyRule[] = [
  {
    ruleId: 'CODE-DYNAMIC-EVAL',
    title: 'Dynamic Code Execution via eval() or new Function()',
    severity: 'high',
    extensions: ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'],
    pattern: new RegExp('(?<![\'"`\\\\])\\b(?:eval\\s*\\(\\s*[^)\\s]|new\\s+Function\\s*\\(\\s*[^)\\s])'),
    description:
      'Dynamic string evaluation enables arbitrary code execution and breaks static security guarantees.',
    remediation:
      'Replace eval() / new Function() with JSON.parse(), a safe expression parser, or explicit dispatch tables.',
  },
  {
    ruleId: 'CODE-SHELL-INJECTION',
    title: 'Interpolated Shell Command in child_process Execution',
    severity: 'critical',
    extensions: ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'],
    pattern: new RegExp('\\b(?:exec|execSync)\\s*\\(\\s*`[^`]*\\$\\{'),
    description:
      'Template literal interpolation inside shell exec() exposes the process to OS command injection.',
    remediation:
      'Use execFile() / spawn() with an explicit argument array and `shell: false` instead of string interpolation.',
  },
  {
    ruleId: 'CODE-SQL-TEMPLATE-INJECTION',
    title: 'Raw SQL Query Built With String Interpolation',
    severity: 'critical',
    extensions: ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.py'],
    pattern: new RegExp(
      '(?:`\\s*(?:SELECT|INSERT\\s+INTO|UPDATE|DELETE\\s+FROM)\\b[^`]*\\$\\{|f["\']\\s*(?:SELECT|INSERT\\s+INTO|UPDATE|DELETE\\s+FROM)\\b[^"\']*\\{)',
      'i',
    ),
    description:
      'Interpolating variables directly into raw SQL statements creates direct SQL Injection risk.',
    remediation:
      'Use parameterized queries (`$1`, `?`) or prepared statements in your database driver/ORM.',
  },
  {
    ruleId: 'CODE-TLS-DISABLED',
    title: 'TLS Certificate Verification Explicitly Disabled',
    severity: 'high',
    extensions: ['.js', '.ts', '.mjs', '.cjs', '.py'],
    pattern: new RegExp(
      "(?:NODE_TLS_REJECT_UNAUTHORIZED\\s*=\\s*['\"]0['\"]|rejectUnauthorized\\s*:\\s*false|verify\\s*=\\s*False)",
    ),
    description:
      'Disabling TLS certificate validation allows trivial man-in-the-middle interception of outbound traffic and API tokens.',
    remediation:
      'Enable strict TLS verification and configure custom CA certificates properly if using internal CAs.',
  },
  {
    ruleId: 'CODE-UNSAFE-HTML-SINK',
    title: 'Unvalidated Raw HTML Injection Sink',
    severity: 'medium',
    extensions: ['.jsx', '.tsx', '.js', '.ts'],
    pattern: new RegExp('(?:dangerouslySetInnerHTML\\s*=|\\.innerHTML\\s*=\\s*[^"\'\\s])'),
    description:
      'Rendering raw HTML directly into the DOM can trigger Cross-Site Scripting (XSS) if untrusted data reaches this sink.',
    remediation:
      'Sanitize HTML via DOMPurify before rendering or render structured React/DOM text nodes directly.',
  },
  {
    ruleId: 'CODE-PY-UNSAFE-EXEC',
    title: 'Unsafe Deserialization or Shell Execution in Python',
    severity: 'critical',
    extensions: ['.py'],
    pattern: new RegExp(
      '(?:\\bpickle\\.loads?\\s*\\(|\\bsubprocess\\.(?:Popen|run|call|check_output)\\s*\\([^)]*shell\\s*=\\s*True)',
    ),
    description:
      'Untrusted pickle deserialization or `shell=True` subprocess calls allow remote command execution.',
    remediation:
      'Use JSON/Pydantic validation instead of pickle, and pass argument lists with `shell=False` to subprocess.',
  },
];

function parseSimpleIgnoreRules(content: string): RegExp[] {
  const regexes: RegExp[] = [];
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith('!')) continue;
    const cleaned = line.replace(/^\//, '').replace(/\/$/, '');
    const escaped = cleaned
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*\*/g, '.*')
      .replace(/\*/g, '[^/]*');
    regexes.push(new RegExp(`(^|/)${escaped}($|/)`));
  }
  return regexes;
}

function isPathIgnored(path: string, patterns: RegExp[]): boolean {
  return patterns.some((re) => re.test(path));
}

function getExtension(path: string): string {
  const base = path.split('/').pop() ?? '';
  const dot = base.lastIndexOf('.');
  return dot >= 0 ? base.slice(dot).toLowerCase() : '';
}

export function analyzeContextAndCode(files: VirtualFile[]): {
  totalBytes: number;
  totalTokens: number;
  optimizableTokens: number;
  tokenSavingsPercent: number;
  topTokenFiles: TokenFileStat[];
  stack: DetectedStack;
  findings: Finding[];
} {
  const findings: Finding[] = [];
  let seq = 1;

  const aiIgnoreFile = files.find(
    (f) => f.path === '.aiignore' || f.path === '.cursorignore' || f.path === '.claudeignore',
  );
  const aiIgnorePatterns = aiIgnoreFile ? parseSimpleIgnoreRules(aiIgnoreFile.content) : [];

  const hasAgentsMd = files.some(
    (f) =>
      f.path === 'AGENTS.md' ||
      f.path === 'CLAUDE.md' ||
      f.path === '.cursorrules' ||
      f.path.startsWith('.cursor/rules/'),
  );
  const hasGitignore = files.some((f) => f.path === '.gitignore');
  const hasMcpConfig = files.some(
    (f) =>
      f.path.endsWith('.mcp.json') ||
      f.path.endsWith('/mcp.json') ||
      f.path === 'mcp.json' ||
      f.path.endsWith('claude_desktop_config.json'),
  );

  const languagesSet = new Set<string>();
  const frameworksSet = new Set<string>();
  const pkgManagersSet = new Set<string>();
  const topDirsSet = new Set<string>();

  let totalBytes = 0;
  let totalTokens = 0;
  let optimizableTokens = 0;
  const fileStats: TokenFileStat[] = [];

  for (const file of files) {
    const bytes = file.sizeBytes ?? new TextEncoder().encode(file.content).length;
    const tokens = Math.max(1, Math.ceil(bytes / 4));
    const shieldedByAiIgnore = isPathIgnored(file.path, aiIgnorePatterns);

    const parts = file.path.split('/');
    if (parts.length > 1) {
      topDirsSet.add(parts[0]);
    }

    const baseName = parts[parts.length - 1];
    const ext = getExtension(file.path);

    if (ext === '.ts' || ext === '.tsx') languagesSet.add('TypeScript');
    else if (ext === '.js' || ext === '.jsx' || ext === '.mjs') languagesSet.add('JavaScript');
    else if (ext === '.py') languagesSet.add('Python');
    else if (ext === '.rs') languagesSet.add('Rust');
    else if (ext === '.go') languagesSet.add('Go');
    else if (ext === '.sol') languagesSet.add('Solidity');

    if (baseName === 'package-lock.json') pkgManagersSet.add('npm');
    if (baseName === 'pnpm-lock.yaml') pkgManagersSet.add('pnpm');
    if (baseName === 'yarn.lock') pkgManagersSet.add('yarn');
    if (baseName === 'bun.lock' || baseName === 'bun.lockb') pkgManagersSet.add('bun');
    if (baseName === 'requirements.txt' || baseName === 'pyproject.toml') pkgManagersSet.add('pip/uv');
    if (baseName === 'Cargo.toml') pkgManagersSet.add('cargo');

    if (baseName === 'package.json') {
      if (pkgManagersSet.size === 0) pkgManagersSet.add('npm');
      try {
        const pkg = JSON.parse(file.content) as Record<string, Record<string, string>>;
        const allDeps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
        if (allDeps.next) frameworksSet.add('Next.js');
        if (allDeps.react) frameworksSet.add('React');
        if (allDeps.vue) frameworksSet.add('Vue');
        if (allDeps.svelte) frameworksSet.add('Svelte');
        if (allDeps.vite) frameworksSet.add('Vite');
        if (allDeps.tailwindcss) frameworksSet.add('Tailwind CSS');
        if (allDeps.express) frameworksSet.add('Express');
        if (allDeps.fastify) frameworksSet.add('Fastify');
      } catch {
        // Ignore malformed JSON
      }
    }

    let isBloat = false;
    let bloatReason: string | undefined;

    if (!shieldedByAiIgnore) {
      if (BLOAT_FILE_NAMES.has(baseName)) {
        isBloat = true;
        bloatReason = 'Unshielded dependency lockfile drains LLM context window';
      } else if (
        file.path.endsWith('.min.js') ||
        file.path.endsWith('.min.css') ||
        file.path.endsWith('.map')
      ) {
        isBloat = true;
        bloatReason = 'Minified bundle / sourcemap pollutes AI token budget';
      } else if ((ext === '.svg' || ext === '.json' || ext === '.csv') && tokens > 6000) {
        isBloat = true;
        bloatReason = `Large data/asset file (${tokens.toLocaleString()} tokens) not excluded in .aiignore`;
      }
    }

    if (!shieldedByAiIgnore) {
      totalBytes += bytes;
      totalTokens += tokens;
      if (isBloat) {
        optimizableTokens += tokens;
      }
    }

    fileStats.push({
      path: file.path,
      bytes,
      tokens,
      isBloat,
      bloatReason,
    });

    // Code safety scan (skip RepoXray's own rule file and demo fixtures when dogfooding)
    if (
      file.path === 'src/core/contextAnalyzer.ts' ||
      file.path === 'src/core/demoPreset.ts' ||
      file.path.startsWith('tests/')
    ) {
      continue;
    }

    const applicableRules = CODE_SAFETY_RULES.filter((r) => r.extensions.includes(ext));
    if (applicableRules.length > 0) {
      const lines = file.content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.length > 1000) continue;
        const trimmed = line.trim();
        if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) {
          continue;
        }
        for (const rule of applicableRules) {
          if (rule.pattern.test(line)) {
            findings.push({
              id: `code-${seq++}`,
              ruleId: rule.ruleId,
              category: 'code-safety',
              severity: rule.severity,
              title: rule.title,
              description: rule.description,
              file: file.path,
              line: i + 1,
              evidence: trimmed.slice(0, 110),
              remediation: rule.remediation,
            });
          }
        }
      }
    }
  }

  // AI Readiness & Context findings
  if (!aiIgnoreFile && optimizableTokens >= 1500) {
    findings.push({
      id: `ai-${seq++}`,
      ruleId: 'AI-MISSING-AIIGNORE',
      category: 'ai-context',
      severity: optimizableTokens > 15000 ? 'medium' : 'low',
      title: `Missing .aiignore Wastes ~${optimizableTokens.toLocaleString()} Tokens per Full-Repo Scan`,
      description:
        'Lockfiles, minified bundles, or heavy static JSON/SVG files are exposed to AI coding agents, increasing API token costs and degrading model reasoning.',
      file: '.aiignore',
      remediation:
        'Add the compiled `.aiignore` (or `.cursorignore`) file to exclude lockfiles, secrets, and build outputs.',
    });
  } else if (optimizableTokens >= 4000) {
    findings.push({
      id: `ai-${seq++}`,
      ruleId: 'AI-UNSHIELDED-BLOAT',
      category: 'ai-context',
      severity: 'low',
      title: `${optimizableTokens.toLocaleString()} Optimizable Context Tokens Detected`,
      description:
        'Several heavy non-source files remain unshielded from AI agent context indexing.',
      file: '.aiignore',
      remediation: 'Update `.aiignore` with the compiled exclusion rules from RepoXray.',
    });
  }

  if (!hasAgentsMd) {
    findings.push({
      id: `ai-${seq++}`,
      ruleId: 'AI-NO-GUARDRAIL-MANIFEST',
      category: 'ai-context',
      severity: 'low',
      title: 'No Deterministic AI Guardrail File (AGENTS.md / .cursorrules)',
      description:
        'Repository lacks explicit architectural and security rules for AI coding assistants, increasing risk of hallucinated packages and secret exposure.',
      file: 'AGENTS.md',
      remediation:
        'Commit the RepoXray-compiled `AGENTS.md` to enforce architecture, secret handling, and dependency rules across all AI tools.',
    });
  }

  const topTokenFiles = fileStats.sort((a, b) => b.tokens - a.tokens).slice(0, 15);
  const tokenSavingsPercent =
    totalTokens > 0 ? Math.min(95, Math.round((optimizableTokens / totalTokens) * 100)) : 0;

  return {
    totalBytes,
    totalTokens,
    optimizableTokens,
    tokenSavingsPercent,
    topTokenFiles,
    stack: {
      languages: Array.from(languagesSet),
      frameworks: Array.from(frameworksSet),
      packageManagers: Array.from(pkgManagersSet),
      topDirectories: Array.from(topDirsSet).slice(0, 12),
      hasGitignore,
      hasAiIgnore: Boolean(aiIgnoreFile),
      hasAgentsMd,
      hasMcpConfig,
    },
    findings,
  };
}
