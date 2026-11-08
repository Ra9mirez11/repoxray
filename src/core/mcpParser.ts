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
  env: Record<string, string>;
}

export function isMcpConfigPath(path: string): boolean {
  const lower = path.toLowerCase();
  return (
    lower.endsWith('.mcp.json') ||
    lower.endsWith('/mcp.json') ||
    lower === 'mcp.json' ||
    lower.endsWith('claude_desktop_config.json')
  );
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

    let extractedPackage: ParsedMcpServer['extractedPackage'];

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

      if (
        pkgToken &&
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
    } else if (runner === 'uvx' || runner === 'pipx') {
      let pkgToken: string | undefined;
      for (let i = 0; i < restArgs.length; i++) {
        const a = restArgs[i];
        if ((a === '--from' || a === '--python') && restArgs[i + 1]) {
          if (a === '--from') {
            pkgToken = restArgs[i + 1];
            break;
          }
          i++;
          continue;
        }
        if (a.startsWith('-')) continue;
        pkgToken = a;
        break;
      }

      if (pkgToken && !pkgToken.startsWith('.') && !pkgToken.startsWith('/')) {
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

    results.push({
      serverName,
      runner,
      allArgs: restArgs,
      rawCommandDisplay: tokens.join(' ').slice(0, 110),
      extractedPackage,
      env: envOut,
    });
  }

  return results;
}
