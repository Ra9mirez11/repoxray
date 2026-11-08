export interface ExtractedGitInstall {
  rawSpec: string;
  ecosystem: 'npm' | 'PyPI';
  isCommitShaPinned: boolean;
  commitRef?: string;
  isInsecureTransport: boolean;
}

export interface ParsedMcpServer {
  serverName: string;
  runner: string;
  allArgs: string[];
  rawCommandDisplay: string;
  extractedPackage?: {
    name: string;
    versionSpec: string;
    ecosystem: 'npm' | 'PyPI';
    isUnpinnedAutoInstall: boolean;
  };
  extractedGitInstall?: ExtractedGitInstall;
  env: Record<string, string>;
}

const FULL_COMMIT_SHA_RE = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/i;

export function isMcpConfigPath(path: string): boolean {
  const lower = path.replace(/\\/g, '/').toLowerCase();
  return (
    lower.endsWith('.mcp.json') ||
    lower.endsWith('/mcp.json') ||
    lower === 'mcp.json' ||
    lower.endsWith('claude_desktop_config.json') ||
    lower.endsWith('claude_config.json') ||
    lower.endsWith('mcp_config.json') ||
    lower.endsWith('cline_mcp_settings.json') ||
    lower.endsWith('roo_mcp_settings.json') ||
    lower.endsWith('.zed/settings.json')
  );
}

/**
 * Parses Git / VCS package specifiers across npm/npx/bunx (`github:owner/repo`, `owner/repo`,
 * `git+https://...#<sha>`) and Python uvx/pip (`git+https://...@<sha>`) and checks whether
 * the reference is pinned to an immutable full 40/64-hex commit SHA.
 */
export function parseGitInstallSpec(
  rawToken: string,
  ecosystem: 'npm' | 'PyPI',
): ExtractedGitInstall | null {
  const spec = rawToken.trim();
  if (!spec || spec.startsWith('.') || spec.startsWith('/') || spec.startsWith('-')) {
    return null;
  }

  const lower = spec.toLowerCase();
  const isExplicitGitProtocol =
    lower.startsWith('git+') ||
    lower.startsWith('git://') ||
    lower.startsWith('ssh://git@') ||
    lower.startsWith('git@');

  const isHostedGitUrl =
    /^https?:\/\/(?:www\.)?(?:github\.com|gitlab\.com|bitbucket\.org|codeberg\.org)\/[^/\s]+\/[^/\s]+/i.test(
      spec,
    ) || /^https?:\/\/[^\s]+\.git(?:[#@][^\s]*)?$/i.test(spec);

  const isNpmShorthandPrefix =
    ecosystem === 'npm' &&
    (lower.startsWith('github:') ||
      lower.startsWith('gitlab:') ||
      lower.startsWith('bitbucket:') ||
      lower.startsWith('gist:'));

  // In npm/npx, unscoped package names cannot contain `/`; `owner/repo` (without leading `@`) is GitHub shorthand.
  const isBareNpmGitHubShorthand =
    ecosystem === 'npm' &&
    !spec.startsWith('@') &&
    !spec.includes(':') &&
    /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:#[^\s]+)?$/.test(spec);

  if (
    !isExplicitGitProtocol &&
    !isHostedGitUrl &&
    !isNpmShorthandPrefix &&
    !isBareNpmGitHubShorthand
  ) {
    return null;
  }

  // Exclude tarball archive URLs on GitHub releases (`/archive/` or `.tgz` / `.tar.gz` / `.whl`)
  if (/^https?:\/\/[^\s]+\.(?:tgz|tar\.gz|zip|whl)(?:[#?].*)?$/i.test(spec)) {
    return null;
  }

  const isInsecureTransport = /^(?:http:\/\/|git:\/\/|git\+http:\/\/)/i.test(spec);

  if (ecosystem === 'npm') {
    const hashIdx = spec.indexOf('#');
    const rawRef = hashIdx >= 0 ? spec.slice(hashIdx + 1).trim() : undefined;
    const commitRef = rawRef && rawRef.length > 0 ? rawRef : undefined;
    const isCommitShaPinned = Boolean(commitRef && FULL_COMMIT_SHA_RE.test(commitRef));
    return {
      rawSpec: spec,
      ecosystem: 'npm',
      isCommitShaPinned,
      commitRef,
      isInsecureTransport,
    };
  }

  // PyPI / uvx / pip VCS URLs (`git+https://github.com/owner/repo.git@<rev>#subdirectory=...`)
  const withoutFragment = spec.split('#')[0] ?? spec;
  const repoPathMatch = withoutFragment.match(/^(?:[a-z0-9+.-]+:\/\/[^/]+\/|git@[^:]+:)(.+)$/i);
  const repoPath = repoPathMatch ? repoPathMatch[1] : withoutFragment;
  const atIdx = repoPath.lastIndexOf('@');
  let commitRef: string | undefined;
  if (atIdx > 0) {
    const candidate = repoPath.slice(atIdx + 1).trim();
    if (candidate) commitRef = candidate;
  }

  // Fallback: if someone wrote `#<40-hex-sha>` instead of `@<sha>`, only accept valid @<sha> in Python VCS
  const isCommitShaPinned = Boolean(commitRef && FULL_COMMIT_SHA_RE.test(commitRef));

  return {
    rawSpec: spec,
    ecosystem: 'PyPI',
    isCommitShaPinned,
    commitRef,
    isInsecureTransport,
  };
}

function splitPackageAndVersion(token: string): { name: string; versionSpec: string } {
  const cleaned = token.trim();
  if (cleaned.startsWith('@')) {
    const slashIdx = cleaned.indexOf('/');
    if (slashIdx > 0) {
      const atAfterSlash = cleaned.indexOf('@', slashIdx + 1);
      if (atAfterSlash > slashIdx) {
        return {
          name: cleaned.slice(0, atAfterSlash),
          versionSpec: cleaned.slice(atAfterSlash + 1) || '*',
        };
      }
    }
    return { name: cleaned, versionSpec: '*' };
  }

  const atIdx = cleaned.indexOf('@');
  if (atIdx > 0) {
    return {
      name: cleaned.slice(0, atIdx),
      versionSpec: cleaned.slice(atIdx + 1) || '*',
    };
  }
  return { name: cleaned, versionSpec: '*' };
}

export function parseMcpConfigContent(content: string): ParsedMcpServer[] {
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(content) as Record<string, unknown>;
  } catch {
    return [];
  }

  if (!parsed || typeof parsed !== 'object') return [];

  const serversRoot = (parsed.mcpServers ?? parsed.servers ?? parsed.context_servers) as
    | Record<string, unknown>
    | undefined;
  if (!serversRoot || typeof serversRoot !== 'object' || Array.isArray(serversRoot)) {
    return [];
  }

  const results: ParsedMcpServer[] = [];

  for (const [serverName, rawCfg] of Object.entries(serversRoot)) {
    if (!rawCfg || typeof rawCfg !== 'object' || Array.isArray(rawCfg)) continue;
    const cfg = rawCfg as Record<string, unknown>;

    // Support both string `command: "npx"` and array `command: ["npx", "-y", "pkg"]`
    const tokens: string[] = [];
    if (Array.isArray(cfg.command)) {
      for (const item of cfg.command) {
        if (typeof item === 'string' && item.trim()) tokens.push(item.trim());
      }
    } else if (typeof cfg.command === 'string' && cfg.command.trim()) {
      tokens.push(...cfg.command.trim().split(/\s+/));
    }

    if (Array.isArray(cfg.args)) {
      for (const arg of cfg.args) {
        if (typeof arg === 'string' && arg.trim()) tokens.push(arg.trim());
      }
    }

    const runner = (tokens[0] ?? '').replace(/^.*[/\\]/, '').toLowerCase();
    const restArgs = tokens.slice(1);

    const envOut: Record<string, string> = {};
    if (cfg.env && typeof cfg.env === 'object' && !Array.isArray(cfg.env)) {
      for (const [k, v] of Object.entries(cfg.env as Record<string, unknown>)) {
        if (v !== null && v !== undefined) {
          envOut[k] = String(v);
        }
      }
    }

    // Also capture inline `-e KEY=VAL` / `--env KEY=VAL` / `--env=KEY=VAL` passed via CLI args (e.g. Docker MCPs)
    for (let i = 0; i < restArgs.length; i++) {
      const arg = restArgs[i];
      let kvPair: string | undefined;
      if ((arg === '-e' || arg === '--env') && restArgs[i + 1]?.includes('=')) {
        kvPair = restArgs[i + 1];
        i++;
      } else if (arg.startsWith('--env=') && arg.slice('--env='.length).includes('=')) {
        kvPair = arg.slice('--env='.length);
      }
      if (kvPair) {
        const eqIdx = kvPair.indexOf('=');
        const ek = kvPair.slice(0, eqIdx).trim();
        const ev = kvPair.slice(eqIdx + 1).trim();
        if (ek && !(ek in envOut)) {
          envOut[ek] = ev;
        }
      }
    }

    let extractedPackage: ParsedMcpServer['extractedPackage'];
    let extractedGitInstall: ParsedMcpServer['extractedGitInstall'];

    if (runner === 'npx' || runner === 'bunx') {
      const hasAutoYes = restArgs.some((a) => a === '-y' || a === '--yes' || runner === 'bunx');
      let pkgToken: string | undefined;

      for (let i = 0; i < restArgs.length; i++) {
        const a = restArgs[i];
        if (a === '-y' || a === '--yes' || a === '--quiet' || a === '-q') continue;
        if ((a === '-p' || a === '--package') && restArgs[i + 1]) {
          pkgToken = restArgs[i + 1];
          break;
        }
        if (a.startsWith('--package=')) {
          pkgToken = a.slice('--package='.length);
          break;
        }
        if (a.startsWith('-')) continue;
        pkgToken = a;
        break;
      }

      if (pkgToken) {
        const gitInstall = parseGitInstallSpec(pkgToken, 'npm');
        if (gitInstall) {
          extractedGitInstall = gitInstall;
        } else if (
          !pkgToken.startsWith('.') &&
          !pkgToken.startsWith('/') &&
          !pkgToken.includes('://')
        ) {
          const { name, versionSpec } = splitPackageAndVersion(pkgToken);
          const isPinned = /^\d+\.\d+\.\d+/.test(versionSpec);
          extractedPackage = {
            name,
            versionSpec,
            ecosystem: 'npm',
            isUnpinnedAutoInstall: hasAutoYes && !isPinned,
          };
        }
      }
    } else if (runner === 'uvx' || runner === 'pipx') {
      let pkgToken: string | undefined;
      for (let i = 0; i < restArgs.length; i++) {
        const a = restArgs[i];
        if (a === 'run') continue;
        if ((a === '--from' || a === '--spec') && restArgs[i + 1]) {
          pkgToken = restArgs[i + 1];
          break;
        }
        if (a.startsWith('--from=')) {
          pkgToken = a.slice('--from='.length);
          break;
        }
        if (a.startsWith('--spec=')) {
          pkgToken = a.slice('--spec='.length);
          break;
        }
        if ((a === '--python' || a === '-p' || a === '--with') && restArgs[i + 1]) {
          i++;
          continue;
        }
        if (a.startsWith('-')) continue;
        pkgToken = a;
        break;
      }

      if (pkgToken) {
        const gitInstall = parseGitInstallSpec(pkgToken, 'PyPI');
        if (gitInstall) {
          extractedGitInstall = gitInstall;
        } else if (
          !pkgToken.startsWith('.') &&
          !pkgToken.startsWith('/') &&
          !pkgToken.includes('://')
        ) {
          const pyMatch = pkgToken.match(/^([A-Za-z0-9_.-]+)(?:==([0-9A-Za-z_.-]+))?/);
          if (pyMatch) {
            extractedPackage = {
              name: pyMatch[1],
              versionSpec: pyMatch[2] ?? '*',
              ecosystem: 'PyPI',
              isUnpinnedAutoInstall: !pyMatch[2],
            };
          }
        }
      }
    }

    results.push({
      serverName,
      runner,
      allArgs: restArgs,
      rawCommandDisplay: tokens.join(' ').slice(0, 110),
      extractedPackage,
      extractedGitInstall,
      env: envOut,
    });
  }

  return results;
}
