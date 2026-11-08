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
  if (!branch) {
    const repoRes = await fetch(`https://api.github.com/repos/${owner}/${repo}`, {
      headers: { Accept: 'application/vnd.github+json' },
    });
    if (repoRes.status === 404) {
      throw new Error(`Repository "${owner}/${repo}" was not found or is private.`);
    }
    if (repoRes.status === 403) {
      throw new Error(
        'GitHub public API rate limit reached for your IP. Scan a local folder directly (unlimited) or retry shortly.',
      );
    }
    if (!repoRes.ok) {
      throw new Error(`GitHub API returned HTTP ${repoRes.status}.`);
    }
    const repoMeta = (await repoRes.json()) as { default_branch?: string };
    branch = repoMeta.default_branch ?? 'main';
  }

  onProgress?.(`Fetching file tree (${owner}/${repo}@${branch})...`);
  const treeRes = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/git/trees/${encodeURIComponent(
      branch,
    )}?recursive=1`,
    { headers: { Accept: 'application/vnd.github+json' } },
  );

  if (treeRes.status === 403) {
    throw new Error(
      'GitHub public API rate limit reached for your IP. Scan a local folder directly (unlimited) or retry shortly.',
    );
  }
  if (!treeRes.ok) {
    throw new Error(`Failed to fetch repository tree (HTTP ${treeRes.status}).`);
  }

  const treeJson = (await treeRes.json()) as {
    tree?: Array<{ path: string; type: string; size?: number }>;
  };

  const allBlobs = (treeJson.tree ?? []).filter(
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
      const encodedPath = item.path
        .split('/')
        .map((seg) => encodeURIComponent(seg))
        .join('/');
      const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${encodeURIComponent(
        branch!,
      )}/${encodedPath}`;

      try {
        const res = await fetch(rawUrl);
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
