import type {
  DependencyRecord,
  Ecosystem,
  Finding,
  PackageHealth,
  VirtualFile,
} from './types';

const RISKY_LIFECYCLE_HOOKS = ['preinstall', 'install', 'postinstall', 'preuninstall'];

const SUSPICIOUS_SCRIPT_RE =
  /\b(curl|wget|invoke-webrequest|iwr|powershell|pwsh|bash\s+-c|sh\s+-c|eval|base64|nc\s+|netcat|node\s+-e|python\s+-c|https?:\/\/)/i;

export function cleanSemver(spec: string): string {
  const trimmed = spec.trim();
  const match = trimmed.match(/(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)/);
  return match ? match[1] : '';
}

export function extractDependencies(files: VirtualFile[]): {
  dependencies: DependencyRecord[];
  scriptFindings: Finding[];
} {
  const dependencies: DependencyRecord[] = [];
  const scriptFindings: Finding[] = [];
  let seq = 1;

  // Map exact locked versions from root package-lock.json when available
  const npmLockedVersions = new Map<string, string>();
  const rootLock = files.find((f) => f.path === 'package-lock.json' && f.content.length > 0);
  if (rootLock) {
    try {
      const parsedLock = JSON.parse(rootLock.content) as {
        packages?: Record<string, { version?: string }>;
      };
      if (parsedLock.packages) {
        for (const [pkgKey, meta] of Object.entries(parsedLock.packages)) {
          if (pkgKey.startsWith('node_modules/') && meta?.version) {
            const depName = pkgKey.slice('node_modules/'.length);
            if (!depName.includes('node_modules/')) {
              npmLockedVersions.set(depName, meta.version);
            }
          }
        }
      }
    } catch {
      // Ignore partial/malformed lockfile
    }
  }

  for (const file of files) {
    const baseName = file.path.split('/').pop() ?? file.path;

    // 1. package.json (npm)
    if (baseName === 'package.json') {
      try {
        const pkg = JSON.parse(file.content) as Record<string, unknown>;

        // Check lifecycle scripts
        const scripts = pkg.scripts as Record<string, unknown> | undefined;
        if (scripts && typeof scripts === 'object') {
          for (const hook of RISKY_LIFECYCLE_HOOKS) {
            const cmd = typeof scripts[hook] === 'string' ? (scripts[hook] as string) : '';
            if (!cmd) continue;
            const isHighRisk = SUSPICIOUS_SCRIPT_RE.test(cmd);
            scriptFindings.push({
              id: `sc-hook-${seq++}`,
              ruleId: isHighRisk ? 'SC-MALICIOUS-LIFECYCLE-HOOK' : 'SC-LIFECYCLE-HOOK',
              category: 'supply-chain',
              severity: isHighRisk ? 'critical' : 'medium',
              title: isHighRisk
                ? `High-Risk Shell/Network Command in "${hook}" Script`
                : `Lifecycle Hook "${hook}" Executes Automatically on Install`,
              description: isHighRisk
                ? `The "${hook}" hook in ${file.path} invokes remote network fetch, shell execution, or inline code evaluation during package installation.`
                : `The "${hook}" script runs automatically during npm install unless --ignore-scripts is enforced.`,
              file: file.path,
              evidence: `"${hook}": "${cmd.slice(0, 120)}"`,
              remediation:
                'Remove unnecessary install hooks, audit any binary download scripts, and run `npm ci --ignore-scripts` in CI.',
            });
          }
        }

        const sections: Array<{ key: string; isDev: boolean }> = [
          { key: 'dependencies', isDev: false },
          { key: 'optionalDependencies', isDev: false },
          { key: 'devDependencies', isDev: true },
        ];

        for (const { key, isDev } of sections) {
          const block = pkg[key] as Record<string, unknown> | undefined;
          if (!block || typeof block !== 'object') continue;

          for (const [depName, rawSpec] of Object.entries(block)) {
            const spec = String(rawSpec ?? '').trim();
            if (spec.startsWith('workspace:')) continue;

            if (
              spec === '*' ||
              spec.toLowerCase() === 'latest' ||
              spec.startsWith('http://') ||
              spec.startsWith('https://') ||
              spec.startsWith('git+')
            ) {
              scriptFindings.push({
                id: `sc-unpinned-${seq++}`,
                ruleId: 'SC-UNPINNED-SPEC',
                category: 'supply-chain',
                severity: spec.startsWith('http://') ? 'critical' : 'medium',
                title: `Unpinned or Remote Tarball Dependency "${depName}"`,
                description: `Dependency "${depName}" uses floating or direct URL specifier "${spec}", bypassing deterministic registry version pinning.`,
                file: file.path,
                evidence: `"${depName}": "${spec}"`,
                remediation:
                  'Pin exact semantic version (e.g. `1.2.3`) and commit a deterministic lockfile.',
              });
            }

            dependencies.push({
              name: depName,
              versionSpec: spec,
              resolvedVersion: npmLockedVersions.get(depName) ?? cleanSemver(spec),
              ecosystem: 'npm',
              manifestPath: file.path,
              isDev,
            });
          }
        }
      } catch {
        // Ignore invalid package.json
      }
    }

    // 2. requirements.txt (PyPI)
    if (baseName === 'requirements.txt' || baseName.endsWith('-requirements.txt')) {
      const lines = file.content.split(/\r?\n/);
      for (const rawLine of lines) {
        const line = rawLine.split('#')[0].trim();
        if (!line || line.startsWith('-')) continue;
        const match = line.match(/^([A-Za-z0-9_.-]+)\s*(.*)$/);
        if (!match) continue;
        const [, name, spec] = match;
        dependencies.push({
          name,
          versionSpec: spec || '*',
          resolvedVersion: cleanSemver(spec),
          ecosystem: 'PyPI',
          manifestPath: file.path,
          isDev: baseName.includes('dev'),
        });
      }
    }

    // 3. Cargo.toml (Rust crates.io)
    if (baseName === 'Cargo.toml') {
      let inDeps = false;
      let isDevSection = false;
      for (const rawLine of file.content.split(/\r?\n/)) {
        const line = rawLine.split('#')[0].trim();
        if (!line) continue;
        if (line.startsWith('[')) {
          inDeps =
            line === '[dependencies]' ||
            line === '[dev-dependencies]' ||
            line.endsWith('.dependencies]');
          isDevSection = line === '[dev-dependencies]';
          continue;
        }
        if (!inDeps) continue;
        const simpleMatch = line.match(/^([A-Za-z0-9_-]+)\s*=\s*"([^"]+)"/);
        const tableMatch = line.match(
          /^([A-Za-z0-9_-]+)\s*=\s*\{[^}]*version\s*=\s*"([^"]+)"/,
        );
        const m = simpleMatch ?? tableMatch;
        if (m) {
          dependencies.push({
            name: m[1],
            versionSpec: m[2],
            resolvedVersion: cleanSemver(m[2]),
            ecosystem: 'crates.io',
            manifestPath: file.path,
            isDev: isDevSection,
          });
        }
      }
    }
  }

  return { dependencies, scriptFindings };
}

function mapOsvEcosystem(eco: Ecosystem): string {
  switch (eco) {
    case 'npm':
      return 'npm';
    case 'PyPI':
      return 'PyPI';
    case 'crates.io':
      return 'crates.io';
  }
}

async function fetchWithTimeout(url: string, init: RequestInit, timeoutMs: number): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

export async function auditSupplyChainLive(
  dependencies: DependencyRecord[],
  offline = false,
): Promise<{ packageHealth: PackageHealth[]; findings: Finding[] }> {
  const healthMap = new Map<string, PackageHealth>();
  const findings: Finding[] = [];
  let seq = 1;

  for (const dep of dependencies) {
    const key = `${dep.ecosystem}:${dep.name}`;
    if (!healthMap.has(key)) {
      healthMap.set(key, {
        name: dep.name,
        ecosystem: dep.ecosystem,
        existsInRegistry: true,
        vulnerabilities: [],
      });
    }
  }

  if (offline || dependencies.length === 0) {
    return { packageHealth: Array.from(healthMap.values()), findings };
  }

  // 1. Batch query Google OSV.dev API (zero API key, native CORS)
  const versionedDeps = dependencies.filter((d) => d.resolvedVersion.length > 0).slice(0, 150);
  if (versionedDeps.length > 0) {
    try {
      const queries = versionedDeps.map((d) => ({
        package: {
          name: d.name,
          ecosystem: mapOsvEcosystem(d.ecosystem),
        },
        version: d.resolvedVersion,
      }));

      const res = await fetchWithTimeout(
        'https://api.osv.dev/v1/querybatch',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ queries }),
        },
        5500,
      );

      if (res.ok) {
        const data = (await res.json()) as {
          results?: Array<{ vulns?: Array<{ id: string; modified?: string }> }>;
        };
        const results = data.results ?? [];
        results.forEach((entry, idx) => {
          const vulns = entry.vulns ?? [];
          if (vulns.length === 0) return;
          const dep = versionedDeps[idx];
          const key = `${dep.ecosystem}:${dep.name}`;
          const record = healthMap.get(key);
          const ids = vulns.map((v) => v.id);

          if (record) {
            for (const v of vulns.slice(0, 5)) {
              record.vulnerabilities.push({
                id: v.id,
                summary: `Known vulnerability reported in OSV database (${v.id})`,
                severity: 'high',
                url: `https://osv.dev/vulnerability/${v.id}`,
              });
            }
          }

          findings.push({
            id: `sc-cve-${seq++}`,
            ruleId: 'SC-OSV-VULNERABILITY',
            category: 'supply-chain',
            severity: vulns.length >= 3 ? 'critical' : 'high',
            title: `${vulns.length} Known Vulnerability Advisory(s) in ${dep.name}@${dep.resolvedVersion}`,
            description: `OSV.dev matched ${vulns.length} security advisory(s): ${ids.slice(0, 4).join(', ')}${
              ids.length > 4 ? ` (+${ids.length - 4} more)` : ''
            }.`,
            file: dep.manifestPath,
            evidence: `"${dep.name}": "${dep.versionSpec}"`,
            remediation: `Upgrade "${dep.name}" to a patched release and review https://osv.dev/vulnerability/${ids[0]}.`,
            referenceUrl: `https://osv.dev/vulnerability/${ids[0]}`,
          });
        });
      }
    } catch {
      // Graceful fallback when offline or rate-limited
    }
  }

  // 2. Inspect npm packages on registry.npmjs.org for Slopsquatting (404 / young age) & hidden install scripts
  // Prioritize runtime dependencies first, cap at 35 unique packages for sub-second speed
  const uniqueNpmDeps: DependencyRecord[] = [];
  const seenNpm = new Set<string>();
  const sortedNpm = [...dependencies]
    .filter((d) => d.ecosystem === 'npm')
    .sort((a, b) => Number(a.isDev) - Number(b.isDev));

  for (const d of sortedNpm) {
    if (!seenNpm.has(d.name)) {
      seenNpm.add(d.name);
      uniqueNpmDeps.push(d);
    }
    if (uniqueNpmDeps.length >= 35) break;
  }

  const concurrency = 7;
  let cursor = 0;

  async function worker(): Promise<void> {
    while (cursor < uniqueNpmDeps.length) {
      const idx = cursor++;
      const dep = uniqueNpmDeps[idx];
      const key = `npm:${dep.name}`;
      const record = healthMap.get(key);

      try {
        const encoded = dep.name.startsWith('@')
          ? `@${encodeURIComponent(dep.name.slice(1))}`
          : encodeURIComponent(dep.name);
        const res = await fetchWithTimeout(
          `https://registry.npmjs.org/${encoded}`,
          {
            method: 'GET',
            headers: { Accept: 'application/json' },
          },
          4500,
        );

        if (res.status === 404) {
          if (record) record.existsInRegistry = false;
          findings.push({
            id: `sc-slop-${seq++}`,
            ruleId: 'SC-SLOPSQUATTING-404',
            category: 'supply-chain',
            severity: 'critical',
            title: `Unregistered / Hallucinated Package "${dep.name}" (Slopsquatting Risk)`,
            description: `Package "${dep.name}" returns 404 on registry.npmjs.org. AI models frequently hallucinate plausible package names; an attacker can register this name on npm and execute arbitrary code on anyone installing this repo.`,
            file: dep.manifestPath,
            evidence: `"${dep.name}": "${dep.versionSpec}"`,
            remediation: `Remove "${dep.name}" immediately and replace with the verified official package name.`,
          });
          continue;
        }

        if (!res.ok) continue;

        const meta = (await res.json()) as {
          time?: Record<string, string>;
          'dist-tags'?: Record<string, string>;
          versions?: Record<
            string,
            { scripts?: Record<string, string>; hasInstallScript?: boolean }
          >;
        };

        const createdIso = meta.time?.created;
        if (createdIso && record) {
          record.createdAt = createdIso;
          const ageMs = Date.now() - new Date(createdIso).getTime();
          const ageDays = Math.max(0, Math.floor(ageMs / (1000 * 60 * 60 * 24)));
          record.ageDays = ageDays;

          if (ageDays <= 21) {
            findings.push({
              id: `sc-young-${seq++}`,
              ruleId: 'SC-NEWLY-REGISTERED-PKG',
              category: 'supply-chain',
              severity: 'high',
              title: `Newly Registered Package "${dep.name}" (${ageDays} day(s) old)`,
              description: `Package "${dep.name}" was first published to npm ${ageDays} day(s) ago (${createdIso.slice(
                0,
                10,
              )}). Newly created packages carry elevated typosquatting and slopsquatting risk.`,
              file: dep.manifestPath,
              evidence: `"${dep.name}": "${dep.versionSpec}"`,
              remediation:
                'Verify publisher identity, repository URL, and source code before installing.',
            });
          }
        }

        // Check target or latest version for hidden install scripts
        const latestTag = meta['dist-tags']?.latest;
        const targetVer =
          (dep.resolvedVersion && meta.versions?.[dep.resolvedVersion]
            ? dep.resolvedVersion
            : latestTag) ?? '';
        const verObj = targetVer ? meta.versions?.[targetVer] : undefined;

        if (verObj) {
          const scripts = verObj.scripts ?? {};
          const hookName = RISKY_LIFECYCLE_HOOKS.find((h) => Boolean(scripts[h]));
          if (hookName) {
            const snippet = scripts[hookName] ?? '';
            if (record) {
              record.hasInstallScript = true;
              record.installScriptSnippet = `${hookName}: ${snippet.slice(0, 100)}`;
            }
            if (!dep.isDev && SUSPICIOUS_SCRIPT_RE.test(snippet)) {
              findings.push({
                id: `sc-dep-hook-${seq++}`,
                ruleId: 'SC-DEP-NETWORK-HOOK',
                category: 'supply-chain',
                severity: 'high',
                title: `Dependency "${dep.name}" Runs Network/Shell Command in ${hookName}`,
                description: `External package "${dep.name}@${targetVer}" executes "${snippet.slice(
                  0,
                  80,
                )}" during installation.`,
                file: dep.manifestPath,
                evidence: `${dep.name} -> ${hookName}: ${snippet.slice(0, 90)}`,
                remediation:
                  'Audit whether native binary download is expected for this package or enforce `--ignore-scripts`.',
              });
            }
          }
        }
      } catch {
        // Ignore individual network timeout
      }
    }
  }

  await Promise.all(Array.from({ length: concurrency }, () => worker()));

  return { packageHealth: Array.from(healthMap.values()), findings };
}
