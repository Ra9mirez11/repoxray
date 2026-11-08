import { chmod, lstat, mkdir, readdir, readFile, stat, writeFile } from 'node:fs/promises';
import { basename, join, relative, resolve } from 'node:path';
import { compileShield } from '../core/compiler';
import { isBinaryFileName, SKIP_DIRS } from '../core/fsFilters';
import { fetchGitHubRepoFiles, parseGitHubInput } from '../core/githubFetcher';
import { runRepoXray } from '../core/scanner';
import type { Severity, VirtualFile } from '../core/types';

const ANSI = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
};

/**
 * Strips terminal control & ANSI/OSC escape sequences from untrusted filenames,
 * package names, and code snippets to prevent terminal escape injection.
 */
function stripTerminalEscapes(input: string): string {
  return input.replace(/[\x00-\x1f\x7f-\x9f]/g, ' ');
}

function colorSeverity(sev: Severity): string {
  switch (sev) {
    case 'critical':
      return `${ANSI.bold}${ANSI.red}[CRITICAL]${ANSI.reset}`;
    case 'high':
      return `${ANSI.red}[HIGH]    ${ANSI.reset}`;
    case 'medium':
      return `${ANSI.yellow}[MEDIUM]  ${ANSI.reset}`;
    case 'low':
      return `${ANSI.cyan}[LOW]     ${ANSI.reset}`;
    case 'info':
      return `${ANSI.dim}[INFO]    ${ANSI.reset}`;
  }
}

async function safeWriteLocalFile(dest: string, content: string, force: boolean): Promise<'written' | 'skipped'> {
  try {
    const lst = await lstat(dest);
    if (lst.isSymbolicLink()) {
      throw new Error(`Refusing to write through symbolic link: ${dest}`);
    }
    if (!force) {
      return 'skipped';
    }
  } catch (err: unknown) {
    if (err instanceof Error && err.message.startsWith('Refusing to write')) {
      throw err;
    }
    // ENOENT means file does not exist yet — safe to create
  }

  await writeFile(dest, content, 'utf8');
  return 'written';
}

async function installPreCommitHook(targetDir: string, force: boolean): Promise<void> {
  const rootDir = resolve(targetDir);
  const gitDir = join(rootDir, '.git');

  let isGitRepo = false;
  try {
    const st = await lstat(gitDir);
    isGitRepo = st.isDirectory();
  } catch {
    isGitRepo = false;
  }

  if (!isGitRepo) {
    console.error(`Error: "${rootDir}" does not contain a .git directory.`);
    process.exit(1);
  }

  const hooksDir = join(gitDir, 'hooks');
  await mkdir(hooksDir, { recursive: true });

  const hookPath = join(hooksDir, 'pre-commit');
  const hookScript = [
    '#!/bin/sh',
    '# RepoXray Pre-Commit Security Gate (installed via: npx rxray init-hook)',
    '# Blocks commits introducing leaked credentials, unsafe execution sinks, or MCP risks (<1s offline)',
    'if [ -x "./node_modules/.bin/rxray" ]; then',
    '  ./node_modules/.bin/rxray . --offline --ci',
    'else',
    '  npx --yes rxray . --offline --ci',
    'fi',
    '',
  ].join('\n');

  const status = await safeWriteLocalFile(hookPath, hookScript, force);
  if (status === 'skipped') {
    console.log(
      `${ANSI.yellow}Skipped pre-commit hook (already exists at ${hookPath}; pass --force to overwrite).${ANSI.reset}`,
    );
    return;
  }

  try {
    await chmod(hookPath, 0o755);
  } catch {
    // Ignore chmod no-op on Windows filesystems
  }

  console.log(`${ANSI.green}Installed RepoXray pre-commit gate -> ${hookPath}${ANSI.reset}`);
}

async function walkLocalDirectory(rootDir: string): Promise<VirtualFile[]> {
  const results: VirtualFile[] = [];

  async function walk(currentDir: string): Promise<void> {
    let entries;
    try {
      entries = await readdir(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = join(currentDir, entry.name);
      if (entry.isSymbolicLink()) {
        continue;
      }
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        await walk(fullPath);
      } else if (entry.isFile()) {
        if (isBinaryFileName(entry.name)) continue;

        try {
          const st = await stat(fullPath);
          const relPath = relative(rootDir, fullPath).replace(/\\/g, '/');

          // For oversized files (>300KB, e.g. huge lockfiles), record exact byte size without loading megabytes into string scanner
          if (st.size > 300_000) {
            results.push({
              path: relPath,
              content: '',
              sizeBytes: st.size,
            });
          } else {
            const content = await readFile(fullPath, 'utf8');
            results.push({
              path: relPath,
              content,
              sizeBytes: st.size,
            });
          }
        } catch {
          // Ignore unreadable file
        }
      }
    }
  }

  await walk(rootDir);
  return results;
}

function printHelp(): void {
  console.log(`
${ANSI.bold}${ANSI.cyan}RepoXray${ANSI.reset} — Security, Supply-Chain, Secret & AI Context X-Ray

${ANSI.bold}Usage:${ANSI.reset}
  npx rxray [path | owner/repo] [options]
  npx rxray init-hook [path] [--force]

${ANSI.bold}Commands & Options:${ANSI.reset}
  init-hook            Install fast (<1s) offline Git pre-commit security gate in .git/hooks/pre-commit
  --write-shield       Generate & write .aiignore and AGENTS.md into target directory
  --force              Overwrite existing .aiignore / AGENTS.md / pre-commit hook
  --offline            Skip live OSV.dev & npm registry network checks
  --json               Output raw JSON report (for CI/CD pipelines)
  --ci                 Fail with exit code 1 if Critical/High issues exist or score < 75
  --fail-below <num>   Fail with exit code 1 if score is below <num> (0-100)
  -h, --help           Show this help message
`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.includes('-h') || args.includes('--help')) {
    printHelp();
    return;
  }

  const jsonOutput = args.includes('--json');
  const offline = args.includes('--offline');
  const writeShield = args.includes('--write-shield');
  const force = args.includes('--force');
  const ciMode = args.includes('--ci');

  let failBelow = ciMode ? 75 : 0;
  const failBelowIdx = args.indexOf('--fail-below');
  if (failBelowIdx >= 0 && args[failBelowIdx + 1]) {
    const parsed = Number.parseInt(args[failBelowIdx + 1], 10);
    if (!Number.isNaN(parsed)) failBelow = parsed;
  }

  const positional = args.filter(
    (a, idx) => !a.startsWith('-') && (failBelowIdx < 0 || idx !== failBelowIdx + 1),
  );

  if (positional[0] === 'init-hook') {
    const hookTarget = positional[1] ?? '.';
    await installPreCommitHook(hookTarget, force);
    return;
  }

  const target = positional[0] ?? '.';

  let projectName = '';
  let files: VirtualFile[] = [];
  let localRootDir: string | null = null;

  const ghTarget =
    target.startsWith('http://') || target.startsWith('https://')
      ? parseGitHubInput(target)
      : null;

  // Check if target exists locally first; if not, try parsing as owner/repo on GitHub
  let isLocal = false;
  if (!ghTarget) {
    try {
      const st = await stat(resolve(target));
      isLocal = st.isDirectory();
    } catch {
      isLocal = false;
    }
  }

  if (isLocal) {
    localRootDir = resolve(target);
    projectName = basename(localRootDir);
    files = await walkLocalDirectory(localRootDir);
  } else if (parseGitHubInput(target)) {
    const remote = await fetchGitHubRepoFiles(target, (msg) => {
      if (!jsonOutput) process.stderr.write(`${ANSI.dim}${stripTerminalEscapes(msg)}${ANSI.reset}\r`);
    });
    if (!jsonOutput) process.stderr.write(' '.repeat(72) + '\r');
    projectName = remote.projectName;
    files = remote.files;
  } else {
    console.error(
      `Error: Target "${stripTerminalEscapes(target)}" is neither an existing directory nor a valid GitHub owner/repo.`,
    );
    process.exit(1);
  }

  const report = await runRepoXray(files, {
    projectName,
    offline,
  });

  if (jsonOutput) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    const gradeColor =
      report.score >= 85 ? ANSI.green : report.score >= 70 ? ANSI.yellow : ANSI.red;

    console.log(
      `\n${ANSI.bold}${ANSI.cyan}REPOXRAY AUDIT${ANSI.reset}  ${ANSI.dim}|${ANSI.reset}  Target: ${ANSI.bold}${stripTerminalEscapes(report.projectName)}${ANSI.reset}  ${ANSI.dim}(${report.durationMs} ms)${ANSI.reset}`,
    );
    console.log('─'.repeat(72));
    console.log(
      `Overall Grade:   ${ANSI.bold}${gradeColor}${report.grade} (${report.score}/100)${ANSI.reset}`,
    );
    console.log(
      `Sub-Scores:      Supply-Chain ${report.subScores.supplyChain}  |  Secrets ${report.subScores.secrets}  |  Code ${report.subScores.codeSafety}  |  AI Context ${report.subScores.aiReadiness}`,
    );
    console.log(
      `Footprint:       ${report.totalFiles} files  |  ${report.dependencies.length} dependencies  |  ${report.totalTokens.toLocaleString()} AI tokens (${report.tokenSavingsPercent}% optimizable)`,
    );
    console.log('─'.repeat(72));

    if (report.findings.length === 0) {
      console.log(`${ANSI.green}Zero security, supply-chain, or AI context issues detected.${ANSI.reset}\n`);
    } else {
      console.log(`${ANSI.bold}Findings (${report.findings.length}):${ANSI.reset}\n`);
      for (const f of report.findings.slice(0, 25)) {
        const loc = stripTerminalEscapes(f.line ? `${f.file}:${f.line}` : f.file);
        console.log(`  ${colorSeverity(f.severity)} ${ANSI.bold}${stripTerminalEscapes(f.title)}${ANSI.reset}`);
        console.log(`             ${ANSI.dim}Location:${ANSI.reset} ${loc}  ${ANSI.dim}(${f.ruleId})${ANSI.reset}`);
        if (f.evidence) {
          console.log(`             ${ANSI.dim}Evidence:${ANSI.reset} ${stripTerminalEscapes(f.evidence)}`);
        }
        console.log(`             ${ANSI.dim}Fix:${ANSI.reset}      ${stripTerminalEscapes(f.remediation)}\n`);
      }
      if (report.findings.length > 25) {
        console.log(
          `  ${ANSI.dim}...and ${report.findings.length - 25} additional finding(s). Use --json for full output.${ANSI.reset}\n`,
        );
      }
    }
  }

  if (writeShield && localRootDir) {
    const compiled = compileShield(report);
    const writes: Array<{ name: string; content: string }> = [
      { name: '.aiignore', content: compiled.aiIgnore },
      { name: 'AGENTS.md', content: compiled.agentsMd },
    ];

    for (const item of writes) {
      const dest = join(localRootDir, item.name);
      const status = await safeWriteLocalFile(dest, item.content, force);
      if (status === 'skipped') {
        if (!jsonOutput) {
          console.log(`${ANSI.yellow}Skipped ${item.name} (already exists; pass --force to overwrite).${ANSI.reset}`);
        }
      } else if (!jsonOutput) {
        console.log(`${ANSI.green}Wrote ${item.name} -> ${dest}${ANSI.reset}`);
      }
    }
  }

  const hasCritOrHigh = report.findings.some(
    (f) => f.severity === 'critical' || f.severity === 'high',
  );
  if ((ciMode && hasCritOrHigh) || report.score < failBelow) {
    process.exit(1);
  }
}

main().catch((err: unknown) => {
  console.error('RepoXray fatal error:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
