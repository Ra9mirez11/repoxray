import { IGNORED_PATH_PREFIXES, isBinaryFileName } from './fsFilters';
import type { VirtualFile } from './types';

export interface ParsedGitHubTarget {
  owner: string;
  repo: string;
  branch?: string;
}

interface CachedGitHubSnapshot {
  cachedAt: number;
  projectName: string;
  files: VirtualFile[];
}

const SESSION_CACHE_TTL_MS = 5 * 60 * 1000;
const GITHUB_API_TIMEOUT_MS = 2_800;
const RAW_CDN_TIMEOUT_MS = 4_500;

/**
 * Priority manifest, guardrail, config, CI, and source entrypoint paths probed directly
 * via Fastly CDN (`raw.githubusercontent.com`) whenever `api.github.com` is rate-limited (403)
 * or experiencing a 502/503/504 outage (which lacks CORS headers and triggers `Failed to fetch`).
 */
const RAW_CDN_FALLBACK_PATHS = [
  'package.json',
  'package-lock.json',
  'pnpm-lock.yaml',
  'yarn.lock',
  'requirements.txt',
  'pyproject.toml',
  'Cargo.toml',
  '.gitignore',
  '.aiignore',
  '.cursorignore',
  '.claudeignore',
  'AGENTS.md',
  'CLAUDE.md',
  '.cursorrules',
  '.mcp.json',
  'mcp.json',
  '.env',
  '.env.example',
  'README.md',
  'LICENSE',
  'SECURITY.md',
  'action.yml',
  'index.html',
  'index.js',
  'index.ts',
  'lib/index.js',
  'lib/express.js',
  'src/index.ts',
  'src/index.js',
  'src/main.ts',
  'src/main.tsx',
  'src/web/main.tsx',
  'src/web/App.tsx',
  'src/cli/index.ts',
  'src/core/scanner.ts',
  'src/core/supplyChain.ts',
  'src/core/secretScanner.ts',
  'src/core/contextAnalyzer.ts',
  'src/core/compiler.ts',
  'src/core/mcpParser.ts',
  '.github/workflows/ci.yml',
  '.github/workflows/test.yml',
  '.github/workflows/main.yml',
  '.github/workflows/publish-npm.yml',
];

async function fetchWithTimeout(
  url: string,
  init: RequestInit = {},
  timeoutMs = GITHUB_API_TIMEOUT_MS,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

function readSessionCache(cacheKey: string): { projectName: string; files: VirtualFile[] } | null {
  try {
    if (typeof sessionStorage === 'undefined') return null;
    const raw = sessionStorage.getItem(cacheKey);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as CachedGitHubSnapshot;
    if (Date.now() - parsed.cachedAt > SESSION_CACHE_TTL_MS) {
      sessionStorage.removeItem(cacheKey);
      return null;
    }
    if (parsed.projectName && Array.isArray(parsed.files)) {
      return { projectName: parsed.projectName, files: parsed.files };
    }
  } catch {
    // Ignore storage access or JSON parse errors
  }
  return null;
}

function writeSessionCache(
  cacheKey: string,
  payload: { projectName: string; files: VirtualFile[] },
): void {
  try {
    if (typeof sessionStorage === 'undefined') return;
    const entry: CachedGitHubSnapshot = {
      cachedAt: Date.now(),
      projectName: payload.projectName,
      files: payload.files,
    };
    sessionStorage.setItem(cacheKey, JSON.stringify(entry));
  } catch {
    // Ignore sessionStorage quota limits on large repositories
  }
}

export function parseGitHubInput(input: string): ParsedGitHubTarget | null {
  const cleaned = input.trim().replace(/\/+$/, '').replace(/\.git$/, '');
  if (!cleaned) return null;

  // Match full URL: https://github.com/owner/repo(/tree/branch)
  const urlMatch = cleaned.match(
    /^(?:https?:\/\/)?(?:www\.)?github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)(?:\/tree\/([^/]+))?/i,
  );
  if (urlMatch) {
    return {
      owner: urlMatch[1],
      repo: urlMatch[2],
      branch: urlMatch[3],
    };
  }

  // Match shorthand: owner/repo
  const shortMatch = cleaned.match(/^([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)$/);
  if (shortMatch) {
    return {
      owner: shortMatch[1],
      repo: shortMatch[2],
    };
  }

  return null;
}

function filePriority(path: string): number {
  const base = path.split('/').pop() ?? path;
  if (
    base === 'package.json' ||
    base === 'package-lock.json' ||
    base === 'requirements.txt' ||
    base === 'pyproject.toml' ||
    base === 'Cargo.toml' ||
    base === '.gitignore' ||
    base === '.aiignore' ||
    base === '.cursorignore' ||
    base === 'AGENTS.md' ||
    base === '.cursorrules' ||
    base.endsWith('.mcp.json') ||
    base === 'mcp.json' ||
    base.startsWith('.env')
  ) {
    return 0;
  }
  if (/\.(ts|tsx|js|jsx|mjs|py|rs|go|sol)$/i.test(base)) {
    return 1;
  }
  if (/\.(json|yaml|yml|toml|md)$/i.test(base)) {
    return 2;
  }
  return 3;
}

function buildRawGitHubUrl(owner: string, repo: string, branch: string, filePath: string): string {
  const encodedPath = filePath
    .split('/')
    .map((seg) => encodeURIComponent(seg))
    .join('/');
  return `https://raw.githubusercontent.com/${encodeURIComponent(owner)}/${encodeURIComponent(
    repo,
  )}/${encodeURIComponent(branch)}/${encodedPath}`;
}

function extractReferencedSourcePaths(pkgJsonContent: string): string[] {
  const discovered = new Set<string>();
  try {
    const pkg = JSON.parse(pkgJsonContent) as Record<string, unknown>;
    const candidates: unknown[] = [pkg.main, pkg.module, pkg.types];
    if (typeof pkg.bin === 'string') {
      candidates.push(pkg.bin);
    } else if (pkg.bin && typeof pkg.bin === 'object') {
      candidates.push(...Object.values(pkg.bin as Record<string, unknown>));
    }

    for (const item of candidates) {
      if (typeof item !== 'string') continue;
      const normalized = item.replace(/^\.\//, '').replace(/^\/+/, '');
      if (
        normalized &&
        !IGNORED_PATH_PREFIXES.some((p) => normalized.startsWith(p)) &&
        !isBinaryFileName(normalized)
      ) {
        discovered.add(normalized);
      }
    }
  } catch {
    // Ignore malformed package.json
  }
  return Array.from(discovered);
}

/**
 * Outage & rate-limit resilient fallback that streams repository manifests, security rules,
 * and entrypoints directly from `raw.githubusercontent.com` (Fastly CDN, `ACAO: *`, 0 API quota)
 * when `api.github.com` returns 403/429/5xx or fails CORS due to a GitHub API brownout.
 */
export async function fetchViaRawCdnFallback(
  owner: string,
  repo: string,
  explicitBranch?: string,
  onProgress?: (msg: string) => void,
): Promise<{ projectName: string; files: VirtualFile[] }> {
  onProgress?.(
    `GitHub REST API unavailable — switching to direct Fastly Raw CDN stream for ${owner}/${repo}...`,
  );

  const candidateBranches = explicitBranch
    ? [explicitBranch]
    : ['main', 'master', 'v4', 'canary', 'develop'];

  let resolvedBranch: string | null = null;

  for (const candidate of candidateBranches) {
    const probes = ['package.json', 'README.md', 'README', '.gitignore', 'Cargo.toml', 'pyproject.toml'];
    const checks = await Promise.all(
      probes.map(async (probeFile) => {
        try {
          const res = await fetchWithTimeout(
            buildRawGitHubUrl(owner, repo, candidate, probeFile),
            { method: 'GET' },
            RAW_CDN_TIMEOUT_MS,
          );
          if (res.ok) {
            const text = await res.text();
            return { path: probeFile, content: text };
          }
        } catch {
          // Ignore individual probe error
        }
        return null;
      }),
    );

    const hits = checks.filter((x): x is { path: string; content: string } => x !== null);
    if (hits.length > 0) {
      resolvedBranch = candidate;
      const fileMap = new Map<string, VirtualFile>();
      for (const h of hits) {
        fileMap.set(h.path, {
          path: h.path,
          content: h.content.length > 250_000 ? '' : h.content,
          sizeBytes: h.content.length,
        });
      }

      const remainingQueue = RAW_CDN_FALLBACK_PATHS.filter((p) => !fileMap.has(p));
      const pkgHit = hits.find((h) => h.path === 'package.json');
      if (pkgHit) {
        for (const extra of extractReferencedSourcePaths(pkgHit.content)) {
          if (!fileMap.has(extra) && !remainingQueue.includes(extra)) {
            remainingQueue.push(extra);
          }
        }
      }

      onProgress?.(`Streaming priority manifests & source files via Raw CDN (${owner}/${repo}@${resolvedBranch})...`);

      let cursor = 0;
      const concurrency = 10;
      async function rawWorker(): Promise<void> {
        while (cursor < remainingQueue.length) {
          const idx = cursor++;
          const relPath = remainingQueue[idx];
          try {
            const res = await fetchWithTimeout(
              buildRawGitHubUrl(owner, repo, resolvedBranch!, relPath),
              { method: 'GET' },
              RAW_CDN_TIMEOUT_MS,
            );
            if (res.ok) {
              const text = await res.text();
              const isLockfile = relPath === 'package-lock.json';
              fileMap.set(relPath, {
                path: relPath,
                content: text.length > 250_000 && !isLockfile ? '' : text,
                sizeBytes: text.length,
              });
            }
          } catch {
            // Skip missing optional path
          }
        }
      }

      await Promise.all(Array.from({ length: concurrency }, () => rawWorker()));

      return {
        projectName: `${owner}/${repo}`,
        files: Array.from(fileMap.values()),
      };
    }
  }

  throw new Error(
    `Unable to reach "${owner}/${repo}" (GitHub API is currently degraded/rate-limited and repository was not found on standard branches via CDN). Verify the owner/repo name or scan a local folder.`,
  );
}

export async function fetchGitHubRepoFiles(
  input: string,
  onProgress?: (msg: string) => void,
): Promise<{ projectName: string; files: VirtualFile[] }> {
  const parsed = parseGitHubInput(input);
  if (!parsed) {
    throw new Error(
      'Invalid GitHub repository reference. Enter "owner/repo" or "https://github.com/owner/repo".',
    );
  }

  const { owner, repo } = parsed;
  const cacheKey = `rxray:gh:v1:${owner.toLowerCase()}/${repo.toLowerCase()}:${parsed.branch ?? 'default'}`;
  const cached = readSessionCache(cacheKey);
  if (cached) {
    onProgress?.(`Loaded ${cached.projectName} from session cache (0 GitHub API calls)...`);
    return cached;
  }

  onProgress?.(`Resolving repository metadata for ${owner}/${repo}...`);

  let branch = parsed.branch;
  let treeItems: Array<{ path: string; type: string; size?: number }> | null = null;

  try {
    if (!branch) {
      const repoRes = await fetchWithTimeout(
        `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`,
        { headers: { Accept: 'application/vnd.github+json' } },
        GITHUB_API_TIMEOUT_MS,
      );
      if (repoRes.status === 404) {
        throw new Error(`NOT_FOUND:${owner}/${repo}`);
      }
      if (!repoRes.ok) {
        throw new Error(`GH_API_HTTP_${repoRes.status}`);
      }
      const repoMeta = (await repoRes.json()) as { default_branch?: string };
      branch = repoMeta.default_branch ?? 'main';
    }

    onProgress?.(`Fetching file tree (${owner}/${repo}@${branch})...`);
    const treeRes = await fetchWithTimeout(
      `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(
        repo,
      )}/git/trees/${encodeURIComponent(branch)}?recursive=1`,
      { headers: { Accept: 'application/vnd.github+json' } },
      GITHUB_API_TIMEOUT_MS,
    );

    if (treeRes.status === 404) {
      throw new Error(`NOT_FOUND:${owner}/${repo}`);
    }
    if (!treeRes.ok) {
      throw new Error(`GH_TREE_HTTP_${treeRes.status}`);
    }

    const treeJson = (await treeRes.json()) as {
      tree?: Array<{ path: string; type: string; size?: number }>;
    };
    treeItems = treeJson.tree ?? [];
  } catch (apiErr: unknown) {
    if (apiErr instanceof Error && apiErr.message.startsWith('NOT_FOUND:')) {
      throw new Error(`Repository "${owner}/${repo}" was not found or is private.`);
    }
    // Automatic seamless failover to Fastly Raw CDN when api.github.com throws 403/503/504/CORS TypeError
    const fallbackResult = await fetchViaRawCdnFallback(owner, repo, parsed.branch, onProgress);
    writeSessionCache(cacheKey, fallbackResult);
    return fallbackResult;
  }

  const allBlobs = treeItems.filter(
    (item) =>
      item.type === 'blob' &&
      !IGNORED_PATH_PREFIXES.some((p) => item.path.startsWith(p)) &&
      !isBinaryFileName(item.path),
  );

  // Prioritize manifests, security files, and source code; download up to 90 files via raw CDN
  // while keeping accurate size metadata for heavy lockfiles without downloading 5MB strings
  const sorted = [...allBlobs].sort((a, b) => filePriority(a.path) - filePriority(b.path));
  const toDownload = sorted.filter((b) => (b.size ?? 0) <= 220_000).slice(0, 90);
  const oversizedBlobs = sorted.filter((b) => (b.size ?? 0) > 220_000).slice(0, 20);

  const files: VirtualFile[] = [];

  // Record oversized lockfiles/assets with exact byte size so token bloat telemetry stays exact
  for (const heavy of oversizedBlobs) {
    files.push({
      path: heavy.path,
      content: '',
      sizeBytes: heavy.size ?? 250_000,
    });
  }

  onProgress?.(`Streaming ${toDownload.length} priority source & manifest files from CDN...`);
  let cursor = 0;
  const concurrency = 10;

  async function downloadWorker(): Promise<void> {
    while (cursor < toDownload.length) {
      const idx = cursor++;
      const item = toDownload[idx];
      const rawUrl = buildRawGitHubUrl(owner, repo, branch!, item.path);

      try {
        const res = await fetchWithTimeout(rawUrl, {}, RAW_CDN_TIMEOUT_MS);
        if (res.ok) {
          const text = await res.text();
          files.push({
            path: item.path,
            content: text,
            sizeBytes: item.size ?? text.length,
          });
        }
      } catch {
        // Skip failed file fetch
      }
    }
  }

  await Promise.all(Array.from({ length: concurrency }, () => downloadWorker()));

  const result = {
    projectName: `${owner}/${repo}`,
    files,
  };
  writeSessionCache(cacheKey, result);
  return result;
}
