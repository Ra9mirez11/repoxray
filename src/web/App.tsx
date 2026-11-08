import React, { useEffect, useMemo, useRef, useState } from 'react';
import { compileShield } from '../core/compiler';
import { buildVulnerableDemoRepo } from '../core/demoPreset';
import { fetchGitHubRepoFiles } from '../core/githubFetcher';
import { runRepoXray } from '../core/scanner';
import type {
  CompiledShield,
  FindingCategory,
  Grade,
  ScanReport,
  Severity,
} from '../core/types';
import {
  pickDirectoryNative,
  readDroppedItems,
  readFileListFromInput,
} from './folderReader';

type ActiveTab = 'findings' | 'fix-prompt' | 'guardrails' | 'tokens' | 'share';
type CategoryFilter = 'all' | 'critical-high' | FindingCategory;
type GuardrailDoc = 'agents' | 'cursorrules' | 'aiignore';

const GITHUB_ACTION_YAML = `name: RepoXray Security & Supply-Chain Gate
on: [push, pull_request]

jobs:
  repoxray:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - name: Run RepoXray Gate
        run: npx rxray . --ci --fail-below 80
`;

function gradeTheme(grade: Grade): {
  ring: string;
  text: string;
  bg: string;
  border: string;
} {
  switch (grade) {
    case 'A+':
    case 'A':
      return {
        ring: 'stroke-emerald-400',
        text: 'text-emerald-400',
        bg: 'bg-emerald-500/10',
        border: 'border-emerald-500/30',
      };
    case 'B':
      return {
        ring: 'stroke-sky-400',
        text: 'text-sky-400',
        bg: 'bg-sky-500/10',
        border: 'border-sky-500/30',
      };
    case 'C':
      return {
        ring: 'stroke-amber-400',
        text: 'text-amber-400',
        bg: 'bg-amber-500/10',
        border: 'border-amber-500/30',
      };
    case 'D':
    case 'F':
      return {
        ring: 'stroke-rose-500',
        text: 'text-rose-400',
        bg: 'bg-rose-500/10',
        border: 'border-rose-500/30',
      };
  }
}

function severityBadgeStyle(sev: Severity): string {
  switch (sev) {
    case 'critical':
      return 'bg-rose-500/20 text-rose-300 border-rose-500/50';
    case 'high':
      return 'bg-orange-500/20 text-orange-300 border-orange-500/40';
    case 'medium':
      return 'bg-amber-500/15 text-amber-300 border-amber-500/40';
    case 'low':
      return 'bg-sky-500/15 text-sky-300 border-sky-500/40';
    case 'info':
      return 'bg-slate-700/40 text-slate-300 border-slate-600';
  }
}

function downloadBlob(filename: string, content: string, mimeType = 'text/plain;charset=utf-8') {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function App() {
  const [githubInput, setGithubInput] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [progressText, setProgressText] = useState('');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);

  const [report, setReport] = useState<ScanReport | null>(null);
  const [activeTab, setActiveTab] = useState<ActiveTab>('findings');
  const [categoryFilter, setCategoryFilter] = useState<CategoryFilter>('all');
  const [guardrailDoc, setGuardrailDoc] = useState<GuardrailDoc>('agents');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const compiled: CompiledShield | null = useMemo(
    () => (report ? compileShield(report) : null),
    [report],
  );

  function triggerCopy(key: string, value: string) {
    void navigator.clipboard.writeText(value);
    setCopiedKey(key);
    setTimeout(() => {
      setCopiedKey((prev) => (prev === key ? null : prev));
    }, 1800);
  }

  async function handleGitHubScan(targetRepo: string) {
    const trimmed = targetRepo.trim();
    if (!trimmed) return;
    setErrorMsg(null);
    setIsScanning(true);
    setProgressText(`Connecting to GitHub API (${trimmed})...`);

    try {
      const { projectName, files } = await fetchGitHubRepoFiles(trimmed, (msg) =>
        setProgressText(msg),
      );
      const res = await runRepoXray(files, {
        projectName,
        onProgress: (msg) => setProgressText(msg),
      });
      setReport(res);
      setActiveTab('findings');
      setCategoryFilter('all');

      const nextUrl = new URL(window.location.href);
      nextUrl.searchParams.set('repo', projectName);
      window.history.replaceState({}, '', nextUrl.toString());
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : String(err));
    } finally {
      setIsScanning(false);
      setProgressText('');
    }
  }

  async function handleDemoScan() {
    setErrorMsg(null);
    setIsScanning(true);
    setProgressText('Initializing synthetic AI SaaS repository...');
    try {
      const demoFiles = buildVulnerableDemoRepo();
      const res = await runRepoXray(demoFiles, {
        projectName: 'vibe-saas-billing-starter (Demo)',
        onProgress: (msg) => setProgressText(msg),
      });
      setReport(res);
      setActiveTab('findings');
      setCategoryFilter('all');
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : String(err));
    } finally {
      setIsScanning(false);
      setProgressText('');
    }
  }

  async function handleBrowseLocalFolder() {
    setErrorMsg(null);
    try {
      const picked = await pickDirectoryNative();
      if (!picked) {
        fileInputRef.current?.click();
        return;
      }
      setIsScanning(true);
      setProgressText(`Scanning ${picked.files.length} local files in browser RAM...`);
      const res = await runRepoXray(picked.files, {
        projectName: picked.projectName,
        onProgress: (msg) => setProgressText(msg),
      });
      setReport(res);
      setActiveTab('findings');
      setCategoryFilter('all');
    } catch (err: unknown) {
      if (err instanceof DOMException && err.name === 'AbortError') return;
      setErrorMsg(err instanceof Error ? err.message : String(err));
    } finally {
      setIsScanning(false);
      setProgressText('');
    }
  }

  async function handleFallbackInputFiles(e: React.ChangeEvent<HTMLInputElement>) {
    const list = e.target.files;
    if (!list || list.length === 0) return;
    setErrorMsg(null);
    setIsScanning(true);
    setProgressText('Reading local directory into browser memory...');
    try {
      const { projectName, files } = await readFileListFromInput(list);
      const res = await runRepoXray(files, {
        projectName,
        onProgress: (msg) => setProgressText(msg),
      });
      setReport(res);
      setActiveTab('findings');
      setCategoryFilter('all');
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : String(err));
    } finally {
      setIsScanning(false);
      setProgressText('');
      e.target.value = '';
    }
  }

  async function handleDrop(e: React.DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setIsDragging(false);
    setErrorMsg(null);
    setIsScanning(true);
    setProgressText('Traversing dropped folder in local RAM...');
    try {
      const { projectName, files } = await readDroppedItems(e.dataTransfer);
      if (files.length === 0) {
        throw new Error('No readable text/source files found in dropped selection.');
      }
      const res = await runRepoXray(files, {
        projectName,
        onProgress: (msg) => setProgressText(msg),
      });
      setReport(res);
      setActiveTab('findings');
      setCategoryFilter('all');
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : String(err));
    } finally {
      setIsScanning(false);
      setProgressText('');
    }
  }

  // Auto-run if URL contains ?repo=owner/name
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const repoParam = params.get('repo');
    if (repoParam) {
      setGithubInput(repoParam);
      void handleGitHubScan(repoParam);
    }
  }, []);

  const filteredFindings = useMemo(() => {
    if (!report) return [];
    if (categoryFilter === 'all') return report.findings;
    if (categoryFilter === 'critical-high') {
      return report.findings.filter((f) => f.severity === 'critical' || f.severity === 'high');
    }
    return report.findings.filter((f) => f.category === categoryFilter);
  }, [report, categoryFilter]);

  const inputDirProps = {
    webkitdirectory: '',
    directory: '',
  } as React.InputHTMLAttributes<HTMLInputElement>;

  return (
    <div className="min-h-screen bg-[#060911] text-slate-100 flex flex-col">
      {/* Hidden directory input fallback for Firefox/Safari */}
      <input
        ref={fileInputRef}
        type="file"
        multiple
        className="hidden"
        onChange={handleFallbackInputFiles}
        {...inputDirProps}
      />

      {/* Top Navigation Bar */}
      <header className="border-b border-slate-800/80 bg-[#080d19]/90 backdrop-blur sticky top-0 z-30">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-400/30 flex items-center justify-center">
              <svg
                className="w-5 h-5 text-cyan-400"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
              >
                <path d="M12 2L3 7v6c0 5.25 3.75 10.15 9 11 5.25-.85 9-5.75 9-11V7l-9-5z" />
                <path d="M9 12l2 2 4-4" />
              </svg>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold tracking-tight text-lg text-white">RepoXray</span>
                <span className="text-[11px] font-mono uppercase px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                  Zero-Upload RAM Engine
                </span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">
                Supply-Chain, Slopsquatting, Secret Exposure &amp; AI Context Compiler
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 sm:gap-3">
            <button
              type="button"
              onClick={() => triggerCopy('cli-cmd', 'npx rxray .')}
              className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-md bg-slate-900 border border-slate-700/80 hover:border-cyan-500/50 text-xs font-mono text-slate-300 transition cursor-pointer"
              title="Copy CLI command"
            >
              <span className="text-cyan-400">$</span>
              <span>npx rxray .</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">
                {copiedKey === 'cli-cmd' ? 'COPIED' : 'COPY'}
              </span>
            </button>

            <a
              href="https://github.com/Ra9mirez11/repoxray"
              target="_blank"
              rel="noreferrer"
              className="px-3 py-1.5 rounded-md text-xs font-medium bg-slate-900 hover:bg-slate-800 border border-slate-700/80 text-slate-200 transition"
            >
              GitHub
            </a>

            <a
              href="https://github.com/sponsors/Ra9mirez11"
              target="_blank"
              rel="noreferrer"
              className="px-3 py-1.5 rounded-md text-xs font-semibold bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition"
            >
              Sponsor
            </a>
          </div>
        </div>
      </header>

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-8 space-y-8">
        {/* Hero Intake Grid */}
        <section className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
          {/* Left: Zero-Friction Local Dropzone */}
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setIsDragging(true);
            }}
            onDragLeave={() => setIsDragging(false)}
            onDrop={handleDrop}
            className={`lg:col-span-7 rounded-xl border-2 border-dashed p-6 sm:p-8 transition flex flex-col justify-between ${
              isDragging
                ? 'border-cyan-400 bg-cyan-500/10'
                : 'border-slate-700/80 bg-[#0b111e] hover:border-slate-600'
            }`}
          >
            <div className="space-y-3">
              <div className="inline-flex items-center gap-2 text-xs font-mono text-cyan-400 bg-cyan-500/10 border border-cyan-500/20 px-2.5 py-1 rounded">
                <span>100% LOCAL EXECUTION</span>
                <span className="text-slate-500">|</span>
                <span>0 BYTES SENT TO SERVER</span>
              </div>
              <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white leading-tight">
                X-Ray Any Codebase Before You Run, Deploy, or Attach an AI Agent.
              </h1>
              <p className="text-sm text-slate-400 leading-relaxed">
                Drop a project directory right here. RepoXray audits{' '}
                <span className="text-slate-200 font-medium">OSV vulnerabilities</span>,{' '}
                <span className="text-slate-200 font-medium">
                  AI-hallucinated packages (slopsquatting)
                </span>
                , <span className="text-slate-200 font-medium">exposed .env &amp; MCP secrets</span>
                , and compiles deterministic{' '}
                <code className="text-cyan-300 text-xs">AGENTS.md</code> +{' '}
                <code className="text-cyan-300 text-xs">.aiignore</code> shields in seconds.
              </p>
            </div>

            <div className="mt-6 pt-5 border-t border-slate-800/80 flex flex-wrap items-center gap-3">
              <button
                type="button"
                disabled={isScanning}
                onClick={handleBrowseLocalFolder}
                className="px-4 py-2.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 text-slate-950 font-semibold text-sm transition cursor-pointer"
              >
                Select Local Project Folder
              </button>

              <button
                type="button"
                disabled={isScanning}
                onClick={handleDemoScan}
                className="px-4 py-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-600/80 text-slate-100 font-medium text-sm transition cursor-pointer"
              >
                Run Instant Vulnerable Demo (1s)
              </button>

              <span className="text-xs text-slate-500 font-mono ml-auto hidden sm:inline">
                Or drag &amp; drop folder anywhere in this box
              </span>
            </div>
          </div>

          {/* Right: Public GitHub URL X-Ray + CLI */}
          <div className="lg:col-span-5 rounded-xl border border-slate-800 bg-[#0b111e] p-6 flex flex-col justify-between space-y-5">
            <div className="space-y-3">
              <div className="text-xs font-mono uppercase tracking-wider text-slate-400">
                Remote Public Repository Scan
              </div>
              <h2 className="text-lg font-semibold text-white">Scan Any GitHub URL Instantly</h2>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  void handleGitHubScan(githubInput);
                }}
                className="space-y-3"
              >
                <input
                  type="text"
                  value={githubInput}
                  onChange={(e) => setGithubInput(e.target.value)}
                  placeholder="owner/repo or https://github.com/owner/repo"
                  className="w-full px-3.5 py-2.5 rounded-lg bg-[#060911] border border-slate-700 focus:border-cyan-400 focus:outline-none text-sm font-mono text-slate-100 placeholder:text-slate-600"
                />
                <button
                  type="submit"
                  disabled={isScanning || !githubInput.trim()}
                  className="w-full py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 disabled:opacity-40 text-slate-950 font-semibold text-sm transition cursor-pointer"
                >
                  {isScanning ? 'Scanning Repository...' : 'X-Ray GitHub Repository'}
                </button>
              </form>

              <div className="flex flex-wrap items-center gap-1.5 pt-1">
                <span className="text-xs text-slate-500 mr-1">Quick test:</span>
                {['expressjs/express', 'sindresorhus/ky', 'colinhacks/zod'].map((sample) => (
                  <button
                    key={sample}
                    type="button"
                    disabled={isScanning}
                    onClick={() => {
                      setGithubInput(sample);
                      void handleGitHubScan(sample);
                    }}
                    className="text-xs font-mono px-2 py-0.5 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 cursor-pointer"
                  >
                    {sample}
                  </button>
                ))}
              </div>
            </div>

            <div className="pt-4 border-t border-slate-800/80 space-y-2">
              <div className="text-xs text-slate-400 flex items-center justify-between">
                <span>Terminal &amp; CI/CD Zero-Install CLI:</span>
                <span className="font-mono text-[11px] text-emerald-400">0 runtime deps</span>
              </div>
              <div className="flex items-center justify-between px-3 py-2 rounded-lg bg-[#060911] border border-slate-800 font-mono text-xs text-slate-200">
                <span>npx rxray . --write-shield</span>
                <button
                  type="button"
                  onClick={() => triggerCopy('hero-cli', 'npx rxray . --write-shield')}
                  className="text-cyan-400 hover:text-cyan-300 font-sans font-semibold cursor-pointer"
                >
                  {copiedKey === 'hero-cli' ? 'COPIED' : 'COPY'}
                </button>
              </div>
            </div>
          </div>
        </section>

        {/* Progress / Error Banner */}
        {isScanning && (
          <div className="rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-4 py-3 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-ping" />
              <span className="text-sm font-mono text-cyan-200">
                {progressText || 'Running static & registry telemetry...'}
              </span>
            </div>
            <span className="text-xs font-mono text-cyan-400">CLIENT-SIDE WORKER</span>
          </div>
        )}

        {errorMsg && (
          <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-200 font-mono">
            Error: {errorMsg}
          </div>
        )}

        {/* Main Scan Report Dashboard */}
        {report && compiled && (
          <section className="space-y-6">
            {/* Score + 4 Pillar Telemetry Strip */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
              {/* Overall Grade Card */}
              {(() => {
                const theme = gradeTheme(report.grade);
                const radius = 44;
                const circumference = 2 * Math.PI * radius;
                const dashOffset = circumference - (report.score / 100) * circumference;

                return (
                  <div
                    className={`lg:col-span-4 rounded-xl border ${theme.border} bg-[#0b111e] p-5 flex items-center gap-5`}
                  >
                    <div className="relative w-28 h-28 shrink-0 flex items-center justify-center">
                      <svg className="w-28 h-28 -rotate-90" viewBox="0 0 108 108">
                        <circle
                          cx="54"
                          cy="54"
                          r={radius}
                          className="stroke-slate-800"
                          strokeWidth="8"
                          fill="none"
                        />
                        <circle
                          cx="54"
                          cy="54"
                          r={radius}
                          className={theme.ring}
                          strokeWidth="8"
                          strokeLinecap="round"
                          strokeDasharray={circumference}
                          strokeDashoffset={dashOffset}
                          fill="none"
                        />
                      </svg>
                      <div className="absolute inset-0 flex flex-col items-center justify-center">
                        <span className={`text-2xl font-extrabold font-mono ${theme.text}`}>
                          {report.grade}
                        </span>
                        <span className="text-xs font-mono text-slate-400">{report.score}/100</span>
                      </div>
                    </div>

                    <div className="min-w-0 space-y-1.5">
                      <div className="text-xs font-mono uppercase text-slate-400 truncate">
                        Target Audited
                      </div>
                      <div className="text-lg font-bold text-white truncate" title={report.projectName}>
                        {report.projectName}
                      </div>
                      <div className="flex flex-wrap gap-2 text-xs font-mono text-slate-400">
                        <span>{report.totalFiles} files</span>
                        <span>|</span>
                        <span>{report.dependencies.length} deps</span>
                        <span>|</span>
                        <span className="text-cyan-400">{report.durationMs} ms</span>
                      </div>
                      <div className="text-xs font-mono text-slate-400">
                        Context: {report.totalTokens.toLocaleString()} tokens
                        {report.tokenSavingsPercent > 0 && (
                          <span className="text-amber-400">
                            {' '}
                            (-{report.tokenSavingsPercent}% reducible)
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })()}

              {/* 4 Pillar Sub-Scores */}
              <div className="lg:col-span-8 grid grid-cols-2 sm:grid-cols-4 gap-4">
                {[
                  {
                    label: 'Supply-Chain',
                    score: report.subScores.supplyChain,
                    sub: `${report.dependencies.length} packages checked`,
                  },
                  {
                    label: 'Secret Hygiene',
                    score: report.subScores.secrets,
                    sub: '.env, keys & MCP config',
                  },
                  {
                    label: 'Code Safety',
                    score: report.subScores.codeSafety,
                    sub: 'Injection & eval sinks',
                  },
                  {
                    label: 'AI Readiness',
                    score: report.subScores.aiReadiness,
                    sub: 'AGENTS.md & .aiignore',
                  },
                ].map((pillar) => {
                  const barColor =
                    pillar.score >= 85
                      ? 'bg-emerald-400'
                      : pillar.score >= 70
                        ? 'bg-amber-400'
                        : 'bg-rose-500';
                  return (
                    <div
                      key={pillar.label}
                      className="rounded-xl border border-slate-800 bg-[#0b111e] p-4 flex flex-col justify-between"
                    >
                      <div className="text-xs font-mono text-slate-400">{pillar.label}</div>
                      <div className="my-2 text-2xl font-bold font-mono text-white">
                        {pillar.score}
                        <span className="text-xs text-slate-500 font-normal">/100</span>
                      </div>
                      <div className="space-y-1.5">
                        <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                          <div
                            className={`h-full ${barColor}`}
                            style={{ width: `${pillar.score}%` }}
                          />
                        </div>
                        <div className="text-[11px] text-slate-500 truncate">{pillar.sub}</div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Primary Action Tab Bar */}
            <div className="border-b border-slate-800 flex flex-wrap gap-2">
              {(
                [
                  {
                    id: 'findings',
                    label: `Findings Radar (${report.findings.length})`,
                  },
                  {
                    id: 'fix-prompt',
                    label: 'Zero-Token AI Fix Prompt',
                  },
                  {
                    id: 'guardrails',
                    label: 'Compiled AGENTS.md & .aiignore',
                  },
                  {
                    id: 'tokens',
                    label: 'Token Footprint Map',
                  },
                  {
                    id: 'share',
                    label: 'Badge, CI Gate & Export',
                  },
                ] as Array<{ id: ActiveTab; label: string }>
              ).map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setActiveTab(tab.id)}
                  className={`px-4 py-2.5 text-sm font-medium border-b-2 transition cursor-pointer ${
                    activeTab === tab.id
                      ? 'border-cyan-400 text-cyan-300 bg-cyan-500/5'
                      : 'border-transparent text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {/* TAB 1: FINDINGS RADAR */}
            {activeTab === 'findings' && (
              <div className="space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="flex flex-wrap gap-2">
                    {(
                      [
                        { id: 'all', label: `All (${report.findings.length})` },
                        {
                          id: 'critical-high',
                          label: `Critical & High (${
                            report.findings.filter(
                              (f) => f.severity === 'critical' || f.severity === 'high',
                            ).length
                          })`,
                        },
                        { id: 'supply-chain', label: 'Supply-Chain' },
                        { id: 'secrets', label: 'Secrets & MCP' },
                        { id: 'code-safety', label: 'Code Safety' },
                        { id: 'ai-context', label: 'AI Context' },
                      ] as Array<{ id: CategoryFilter; label: string }>
                    ).map((pill) => (
                      <button
                        key={pill.id}
                        type="button"
                        onClick={() => setCategoryFilter(pill.id)}
                        className={`px-3 py-1 rounded-md text-xs font-mono border transition cursor-pointer ${
                          categoryFilter === pill.id
                            ? 'bg-cyan-500/15 border-cyan-400/50 text-cyan-300'
                            : 'bg-[#0b111e] border-slate-800 text-slate-400 hover:text-slate-200'
                        }`}
                      >
                        {pill.label}
                      </button>
                    ))}
                  </div>

                  {report.findings.length > 0 && (
                    <button
                      type="button"
                      onClick={() => setActiveTab('fix-prompt')}
                      className="px-3.5 py-1.5 rounded-md bg-emerald-500/15 border border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/25 text-xs font-semibold transition cursor-pointer"
                    >
                      Generate 1-Click AI Fix Prompt -&gt;
                    </button>
                  )}
                </div>

                {filteredFindings.length === 0 ? (
                  <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-8 text-center space-y-2">
                    <div className="text-lg font-semibold text-emerald-300">
                      Zero Findings in Selected Category
                    </div>
                    <p className="text-sm text-slate-400">
                      No supply-chain traps, exposed secrets, or unsafe execution sinks matched this
                      filter.
                    </p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {filteredFindings.map((f) => (
                      <div
                        key={f.id}
                        className="rounded-xl border border-slate-800 bg-[#0b111e] p-4 sm:p-5 space-y-2.5"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex items-center gap-2.5">
                            <span
                              className={`text-[11px] font-mono uppercase font-bold px-2 py-0.5 rounded border ${severityBadgeStyle(
                                f.severity,
                              )}`}
                            >
                              {f.severity}
                            </span>
                            <h3 className="font-semibold text-white text-sm sm:text-base">
                              {f.title}
                            </h3>
                          </div>
                          <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
                            <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-cyan-300">
                              {f.line ? `${f.file}:${f.line}` : f.file}
                            </span>
                            <span className="text-slate-500">{f.ruleId}</span>
                          </div>
                        </div>

                        <p className="text-sm text-slate-300">{f.description}</p>

                        {f.evidence && (
                          <div className="px-3 py-2 rounded bg-[#060911] border border-slate-800/90 font-mono text-xs text-amber-300 overflow-x-auto">
                            {f.evidence}
                          </div>
                        )}

                        <div className="pt-1 flex flex-wrap items-center justify-between gap-2 text-xs">
                          <div className="text-emerald-300">
                            <span className="font-semibold uppercase font-mono mr-1.5">Fix:</span>
                            <span className="text-slate-300">{f.remediation}</span>
                          </div>
                          {f.referenceUrl && (
                            <a
                              href={f.referenceUrl}
                              target="_blank"
                              rel="noreferrer"
                              className="font-mono text-cyan-400 hover:underline"
                            >
                              Advisory Details -&gt;
                            </a>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* TAB 2: ZERO-TOKEN AI FIX PROMPT */}
            {activeTab === 'fix-prompt' && (
              <div className="rounded-xl border border-slate-800 bg-[#0b111e] p-5 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <h3 className="text-base font-semibold text-white">
                      Bring-Your-Own-Agent Remediation Prompt ($0 API Token Cost)
                    </h3>
                    <p className="text-xs text-slate-400">
                      Paste directly into Cursor, Claude Code, Antigravity, Windsurf, or ChatGPT to
                      patch every finding with redacted evidence.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => triggerCopy('fix-prompt', compiled.fixPrompt)}
                    className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs transition cursor-pointer"
                  >
                    {copiedKey === 'fix-prompt' ? 'COPIED TO CLIPBOARD' : 'Copy Full Fix Prompt'}
                  </button>
                </div>

                <pre className="p-4 rounded-lg bg-[#060911] border border-slate-800 text-xs font-mono text-slate-200 overflow-x-auto whitespace-pre-wrap max-h-[480px] overflow-y-auto">
                  {compiled.fixPrompt}
                </pre>
              </div>
            )}

            {/* TAB 3: COMPILED GUARDRAILS */}
            {activeTab === 'guardrails' && (
              <div className="rounded-xl border border-slate-800 bg-[#0b111e] p-5 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="flex gap-2">
                    {(
                      [
                        { id: 'agents', label: 'AGENTS.md' },
                        { id: 'aiignore', label: '.aiignore' },
                        { id: 'cursorrules', label: '.cursorrules' },
                      ] as Array<{ id: GuardrailDoc; label: string }>
                    ).map((doc) => (
                      <button
                        key={doc.id}
                        type="button"
                        onClick={() => setGuardrailDoc(doc.id)}
                        className={`px-3 py-1.5 rounded-md text-xs font-mono border cursor-pointer ${
                          guardrailDoc === doc.id
                            ? 'bg-cyan-500/15 border-cyan-400/50 text-cyan-300'
                            : 'bg-[#060911] border-slate-800 text-slate-400'
                        }`}
                      >
                        {doc.label}
                      </button>
                    ))}
                  </div>

                  <div className="flex items-center gap-2">
                    {(() => {
                      const activeContent =
                        guardrailDoc === 'agents'
                          ? compiled.agentsMd
                          : guardrailDoc === 'aiignore'
                            ? compiled.aiIgnore
                            : compiled.cursorRules;
                      const activeFilename =
                        guardrailDoc === 'agents'
                          ? 'AGENTS.md'
                          : guardrailDoc === 'aiignore'
                            ? '.aiignore'
                            : '.cursorrules';

                      return (
                        <>
                          <button
                            type="button"
                            onClick={() => triggerCopy(`doc-${guardrailDoc}`, activeContent)}
                            className="px-3.5 py-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-100 cursor-pointer"
                          >
                            {copiedKey === `doc-${guardrailDoc}` ? 'COPIED' : 'Copy'}
                          </button>
                          <button
                            type="button"
                            onClick={() => downloadBlob(activeFilename, activeContent)}
                            className="px-3.5 py-1.5 rounded-md bg-emerald-500 hover:bg-emerald-400 text-xs font-semibold text-slate-950 cursor-pointer"
                          >
                            Download {activeFilename}
                          </button>
                        </>
                      );
                    })()}
                  </div>
                </div>

                <pre className="p-4 rounded-lg bg-[#060911] border border-slate-800 text-xs font-mono text-slate-200 overflow-x-auto whitespace-pre-wrap max-h-[460px] overflow-y-auto">
                  {guardrailDoc === 'agents'
                    ? compiled.agentsMd
                    : guardrailDoc === 'aiignore'
                      ? compiled.aiIgnore
                      : compiled.cursorRules}
                </pre>
              </div>
            )}

            {/* TAB 4: TOKEN FOOTPRINT MAP */}
            {activeTab === 'tokens' && (
              <div className="rounded-xl border border-slate-800 bg-[#0b111e] p-5 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <h3 className="text-base font-semibold text-white">
                      Largest Context Consumers ({report.totalTokens.toLocaleString()} Active Tokens)
                    </h3>
                    <p className="text-xs text-slate-400">
                      Files highlighted in amber drain LLM context windows without improving code
                      intelligence. Apply the compiled <code className="text-cyan-300">.aiignore</code>{' '}
                      to save {report.optimizableTokens.toLocaleString()} tokens (
                      {report.tokenSavingsPercent}%).
                    </p>
                  </div>
                </div>

                <div className="space-y-2.5">
                  {report.topTokenFiles.map((tf) => {
                    const maxTokens = report.topTokenFiles[0]?.tokens || 1;
                    const widthPct = Math.max(3, Math.round((tf.tokens / maxTokens) * 100));
                    return (
                      <div
                        key={tf.path}
                        className="p-3 rounded-lg bg-[#060911] border border-slate-800/90 space-y-1.5"
                      >
                        <div className="flex items-center justify-between text-xs font-mono">
                          <span className="text-slate-200 truncate">{tf.path}</span>
                          <span className={tf.isBloat ? 'text-amber-400' : 'text-cyan-400'}>
                            {tf.tokens.toLocaleString()} tokens ({(tf.bytes / 1024).toFixed(1)} KB)
                          </span>
                        </div>
                        <div className="w-full h-1.5 bg-slate-900 rounded-full overflow-hidden">
                          <div
                            className={`h-full ${tf.isBloat ? 'bg-amber-400' : 'bg-cyan-500'}`}
                            style={{ width: `${widthPct}%` }}
                          />
                        </div>
                        {tf.bloatReason && (
                          <div className="text-[11px] text-amber-300/90 font-mono">
                            Token Vampire: {tf.bloatReason}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* TAB 5: BADGE, CI GATE & EXPORT */}
            {activeTab === 'share' && (
              <div id="ci-pro" className="grid grid-cols-1 lg:grid-cols-2 gap-5">
                {/* Left: README Badge + Share + Compliance Exports */}
                <div className="rounded-xl border border-slate-800 bg-[#0b111e] p-5 space-y-5">
                  <div className="space-y-2">
                    <h3 className="text-base font-semibold text-white">
                      GitHub README Security Badge
                    </h3>
                    <p className="text-xs text-slate-400">
                      Add your verified RepoXray score badge to your repository README to prove
                      supply-chain and secret hygiene.
                    </p>
                    <div className="p-4 rounded-lg bg-[#060911] border border-slate-800 flex items-center justify-between gap-4">
                      <img
                        src={`data:image/svg+xml;utf8,${encodeURIComponent(compiled.badgeSvg)}`}
                        alt="RepoXray Security Badge"
                        className="h-[22px] w-auto"
                      />
                      <span className="text-xs font-mono text-slate-500">Live SVG Preview</span>
                    </div>
                    <div className="flex flex-wrap gap-2 pt-1">
                      <button
                        type="button"
                        onClick={() => triggerCopy('badge-md', compiled.badgeMarkdown)}
                        className="px-3 py-1.5 rounded-md bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-semibold cursor-pointer"
                      >
                        {copiedKey === 'badge-md' ? 'COPIED MARKDOWN' : 'Copy README Markdown'}
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          downloadBlob('repoxray-badge.svg', compiled.badgeSvg, 'image/svg+xml')
                        }
                        className="px-3 py-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold cursor-pointer"
                      >
                        Download Badge .SVG
                      </button>
                    </div>
                  </div>

                  <div className="pt-4 border-t border-slate-800 space-y-2">
                    <h4 className="text-sm font-semibold text-white">
                      Share Scorecard &amp; Export Audit Report
                    </h4>
                    <pre className="p-3 rounded-lg bg-[#060911] border border-slate-800 text-xs font-mono text-slate-300 whitespace-pre-wrap">
                      {compiled.shareSummary}
                    </pre>
                    <div className="flex flex-wrap gap-2">
                      <button
                        type="button"
                        onClick={() => triggerCopy('share-post', compiled.shareSummary)}
                        className="px-3 py-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-100 cursor-pointer"
                      >
                        {copiedKey === 'share-post' ? 'COPIED SUMMARY' : 'Copy X / Reddit Summary'}
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          downloadBlob(
                            `${report.projectName.replace(/[^a-z0-9-_]/gi, '_')}-repoxray.md`,
                            compiled.markdownReport,
                          )
                        }
                        className="px-3 py-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-100 cursor-pointer"
                      >
                        Export Audit (.MD)
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          downloadBlob(
                            `${report.projectName.replace(/[^a-z0-9-_]/gi, '_')}-repoxray.json`,
                            JSON.stringify(report, null, 2),
                            'application/json',
                          )
                        }
                        className="px-3 py-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-100 cursor-pointer"
                      >
                        Export JSON (CI / SOC2)
                      </button>
                    </div>
                  </div>
                </div>

                {/* Right: GitHub Actions CI Gate + Sponsorship */}
                <div className="rounded-xl border border-slate-800 bg-[#0b111e] p-5 space-y-5">
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <h3 className="text-base font-semibold text-white">
                        Automated GitHub Actions Pull Request Gate
                      </h3>
                      <button
                        type="button"
                        onClick={() => triggerCopy('gh-action', GITHUB_ACTION_YAML)}
                        className="text-xs font-mono text-cyan-400 hover:text-cyan-300 cursor-pointer"
                      >
                        {copiedKey === 'gh-action' ? 'COPIED YAML' : 'COPY YAML'}
                      </button>
                    </div>
                    <p className="text-xs text-slate-400">
                      Drop into <code className="text-cyan-300">.github/workflows/repoxray.yml</code>{' '}
                      to automatically block PRs that introduce hallucinated packages, CVEs, or
                      leaked secrets.
                    </p>
                    <pre className="p-3 rounded-lg bg-[#060911] border border-slate-800 text-xs font-mono text-slate-300 overflow-x-auto">
                      {GITHUB_ACTION_YAML}
                    </pre>
                  </div>

                  <div className="p-4 rounded-lg border border-cyan-500/30 bg-cyan-500/5 space-y-2">
                    <div className="text-xs font-mono uppercase text-cyan-400">
                      Open-Core Sustainability &amp; Enterprise Support
                    </div>
                    <div className="text-sm font-semibold text-white">
                      Back RepoXray Development or Unlock Team Policy Rules
                    </div>
                    <p className="text-xs text-slate-400 leading-relaxed">
                      RepoXray is 100% free and open-source for developers. Engineering teams can
                      sponsor ongoing vulnerability signature research via GitHub Sponsors or license
                      centralized organization policy packs via Polar.sh.
                    </p>
                  </div>
                </div>
              </div>
            )}
          </section>
        )}
      </main>

      <footer className="border-t border-slate-800/80 py-5 mt-12 text-center text-xs font-mono text-slate-500">
        RepoXray Engine v0.2.0 — 100% Client-Side Execution | Powered by OSV.dev &amp; Public
        Registry Telemetry | CLI: npx rxray
      </footer>
    </div>
  );
}
