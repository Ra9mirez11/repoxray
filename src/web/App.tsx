import React, { useEffect, useMemo, useRef, useState } from 'react';
import { compileShield } from '../core/compiler';
import { buildVulnerableDemoRepo } from '../core/demoPreset';
import { fetchGitHubRepoFiles } from '../core/githubFetcher';
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
import { executeRepoXrayScan } from './workerClient';

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
      - name: Run RepoXray Gate
        uses: Ra9mirez11/repoxray@main
        with:
          fail-below: '85'
`;

function gradeTheme(grade: Grade): {
  ring: string;
  text: string;
  bg: string;
  border: string;
  glow: string;
} {
  switch (grade) {
    case 'A+':
    case 'A':
      return {
        ring: 'stroke-emerald-400',
        text: 'text-emerald-400',
        bg: 'bg-emerald-500/10',
        border: 'border-emerald-400/30',
        glow: 'shadow-[0_0_40px_-12px_rgba(16,185,129,0.35)]',
      };
    case 'B':
      return {
        ring: 'stroke-sky-400',
        text: 'text-sky-400',
        bg: 'bg-sky-500/10',
        border: 'border-sky-400/30',
        glow: 'shadow-[0_0_40px_-12px_rgba(56,189,248,0.35)]',
      };
    case 'C':
      return {
        ring: 'stroke-amber-400',
        text: 'text-amber-400',
        bg: 'bg-amber-500/10',
        border: 'border-amber-400/30',
        glow: 'shadow-[0_0_40px_-12px_rgba(245,158,11,0.3)]',
      };
    case 'D':
    case 'F':
      return {
        ring: 'stroke-rose-500',
        text: 'text-rose-400',
        bg: 'bg-rose-500/10',
        border: 'border-rose-500/35',
        glow: 'shadow-[0_0_40px_-12px_rgba(244,63,94,0.35)]',
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
  const [offlineMode, setOfflineMode] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [progressText, setProgressText] = useState('');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);

  const [report, setReport] = useState<ScanReport | null>(null);
  const [activeTab, setActiveTab] = useState<ActiveTab>('findings');
  const [categoryFilter, setCategoryFilter] = useState<CategoryFilter>('all');
  const [guardrailDoc, setGuardrailDoc] = useState<GuardrailDoc>('agents');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [hasCopiedFixPrompt, setHasCopiedFixPrompt] = useState(false);

  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const compiled: CompiledShield | null = useMemo(
    () => (report ? compileShield(report) : null),
    [report],
  );

  function triggerCopy(key: string, value: string) {
    void navigator.clipboard.writeText(value);
    setCopiedKey(key);
    if (key === 'fix-prompt') {
      setHasCopiedFixPrompt(true);
    }
    setTimeout(() => {
      setCopiedKey((prev) => (prev === key ? null : prev));
    }, 2200);
  }

  async function handleGitHubScan(targetRepo: string, forceOffline?: boolean) {
    const trimmed = targetRepo.trim();
    if (!trimmed) return;
    setErrorMsg(null);
    setIsScanning(true);
    setProgressText(`Connecting to GitHub API (${trimmed})...`);

    try {
      const { projectName, files } = await fetchGitHubRepoFiles(trimmed, (msg) =>
        setProgressText(msg),
      );
      const res = await executeRepoXrayScan(files, {
        projectName,
        offline: forceOffline ?? offlineMode,
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
    setProgressText('Initializing synthetic AI SaaS repository in Web Worker...');
    try {
      const demoFiles = buildVulnerableDemoRepo();
      const res = await executeRepoXrayScan(demoFiles, {
        projectName: 'vibe-saas-billing-starter (Demo)',
        offline: offlineMode,
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
      setProgressText(`Scanning ${picked.files.length} local files in dedicated Web Worker...`);
      const res = await executeRepoXrayScan(picked.files, {
        projectName: picked.projectName,
        offline: offlineMode,
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
    setProgressText('Reading local directory into bounded RAM buffer...');
    try {
      const { projectName, files } = await readFileListFromInput(list);
      const res = await executeRepoXrayScan(files, {
        projectName,
        offline: offlineMode,
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
    setProgressText('Traversing dropped folder in bounded RAM...');
    try {
      const { projectName, files } = await readDroppedItems(e.dataTransfer);
      if (files.length === 0) {
        throw new Error('No readable text/source files found in dropped selection.');
      }
      const res = await executeRepoXrayScan(files, {
        projectName,
        offline: offlineMode,
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
    <div className="relative min-h-screen bg-[#04070d] text-slate-100 flex flex-col overflow-x-hidden">
      {/* Ambient Aceternity / Linear Radial Spotlights + Architectural Grid (Zero CLS) */}
      <div
        aria-hidden="true"
        className="pointer-events-none fixed inset-0 rx-grid-backdrop z-0"
      />
      <div
        aria-hidden="true"
        className="pointer-events-none fixed inset-x-0 top-0 h-[560px] rx-spotlight z-0"
      />

      {/* Hidden directory input fallback for Firefox/Safari */}
      <input
        ref={fileInputRef}
        type="file"
        multiple
        className="hidden"
        onChange={handleFallbackInputFiles}
        {...inputDirProps}
      />

      {/* Top Glassmorphic Navigation Bar */}
      <header className="border-b border-white/10 bg-[#050912]/80 backdrop-blur-md sticky top-0 z-30">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <a
              href="/"
              aria-label="RepoXray Home"
              className="w-10 h-10 shrink-0 rounded-xl shadow-[0_0_24px_-4px_rgba(34,211,238,0.45)] hover:shadow-[0_0_28px_-2px_rgba(52,211,153,0.55)] transition-shadow flex items-center justify-center"
            >
              <svg
                className="w-10 h-10"
                viewBox="0 0 64 64"
                fill="none"
                aria-hidden="true"
              >
                <defs>
                  <linearGradient id="nav-rx-bg" x1="4" y1="4" x2="60" y2="60" gradientUnits="userSpaceOnUse">
                    <stop offset="0%" stopColor="#081226" />
                    <stop offset="100%" stopColor="#040811" />
                  </linearGradient>
                  <linearGradient id="nav-rx-rim" x1="2" y1="2" x2="62" y2="62" gradientUnits="userSpaceOnUse">
                    <stop offset="0%" stopColor="#38bdf8" />
                    <stop offset="100%" stopColor="#10b981" />
                  </linearGradient>
                  <linearGradient id="nav-rx-x1" x1="18" y1="18" x2="46" y2="46" gradientUnits="userSpaceOnUse">
                    <stop offset="0%" stopColor="#ffffff" />
                    <stop offset="50%" stopColor="#38bdf8" />
                    <stop offset="100%" stopColor="#10b981" />
                  </linearGradient>
                  <linearGradient id="nav-rx-x2" x1="46" y1="18" x2="18" y2="46" gradientUnits="userSpaceOnUse">
                    <stop offset="0%" stopColor="#67e8f9" />
                    <stop offset="100%" stopColor="#34d399" />
                  </linearGradient>
                </defs>
                <rect x="2" y="2" width="60" height="60" rx="14" fill="url(#nav-rx-bg)" stroke="url(#nav-rx-rim)" strokeWidth="2.2" />
                <g stroke="#38bdf8" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M11 20v-6a3 3 0 0 1 3-3h6" />
                  <path d="M44 11h6a3 3 0 0 1 3 3v6" />
                  <path d="M11 44v6a3 3 0 0 0 3 3h6" />
                  <path d="M44 53h6a3 3 0 0 0 3-3v-6" />
                </g>
                <path d="M19.5 19.5L44.5 44.5" stroke="url(#nav-rx-x1)" strokeWidth="6.5" strokeLinecap="round" />
                <path d="M44.5 19.5L19.5 44.5" stroke="url(#nav-rx-x2)" strokeWidth="6.5" strokeLinecap="round" />
                <line x1="7" y1="32" x2="57" y2="32" stroke="#10b981" strokeOpacity="0.38" strokeWidth="6" strokeLinecap="round" />
                <line x1="8" y1="32" x2="56" y2="32" stroke="#6ee7b7" strokeWidth="2.6" strokeLinecap="round" />
                <circle cx="32" cy="32" r="5.6" fill="#050b16" stroke="#34d399" strokeWidth="2.4" />
                <circle cx="32" cy="32" r="2.3" fill="#ffffff" />
              </svg>
            </a>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold tracking-tight text-lg text-white">RepoXray</span>
                <span className="text-[11px] font-mono uppercase px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-300 border border-emerald-400/30">
                  Zero-Upload Worker
                </span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">
                Supply-Chain, Malware Tombstone, Secret &amp; AI Guardrail Compiler
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 sm:gap-2.5">
            <button
              type="button"
              onClick={() => triggerCopy('cli-cmd', 'npx rxray .')}
              className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-md bg-white/[0.03] border border-white/10 hover:border-cyan-400/40 text-xs font-mono text-slate-200 transition cursor-pointer"
              title="Copy 5-letter CLI command"
            >
              <span className="text-cyan-400">$</span>
              <span>npx rxray .</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-white/10 text-cyan-300">
                {copiedKey === 'cli-cmd' ? 'COPIED' : 'COPY'}
              </span>
            </button>

            <a
              href="https://www.npmjs.com/package/rxray"
              target="_blank"
              rel="noreferrer"
              className="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-mono bg-white/[0.03] hover:bg-white/[0.07] border border-white/10 text-slate-300 transition"
            >
              <span>npm:rxray</span>
            </a>

            <a
              href="https://github.com/Ra9mirez11/repoxray"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-white/[0.04] hover:bg-white/[0.09] border border-white/10 text-slate-200 transition"
            >
              <svg className="w-3.5 h-3.5 text-amber-300" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z" />
              </svg>
              <span>GitHub</span>
            </a>

            <a
              href="https://github.com/sponsors/Ra9mirez11"
              target="_blank"
              rel="noreferrer"
              className="px-3 py-1.5 rounded-md text-xs font-semibold bg-gradient-to-r from-cyan-400 to-emerald-400 hover:from-cyan-300 hover:to-emerald-300 text-slate-950 shadow-[0_0_20px_-5px_rgba(34,211,238,0.55)] transition"
            >
              Sponsor
            </a>
          </div>
        </div>
      </header>

      <main className="relative z-10 flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-8 space-y-8">
        {/* Hero Intake Bento Grid */}
        <section className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
          {/* Left: Zero-Friction Local Dropzone */}
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setIsDragging(true);
            }}
            onDragLeave={() => setIsDragging(false)}
            onDrop={handleDrop}
            className={`relative overflow-hidden lg:col-span-7 rounded-2xl p-6 sm:p-8 flex flex-col justify-between transition ${
              isDragging
                ? 'border-2 border-dashed border-cyan-400 bg-cyan-500/10 shadow-[0_0_50px_-10px_rgba(34,211,238,0.35)]'
                : 'rx-bento-card'
            }`}
          >
            {/* Top Specular Hairline */}
            <div
              aria-hidden="true"
              className="pointer-events-none absolute inset-x-10 top-0 h-px bg-gradient-to-r from-transparent via-cyan-400/50 to-transparent"
            />

            <div className="space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="inline-flex items-center gap-2 text-[11px] font-mono text-cyan-300 bg-cyan-500/10 border border-cyan-400/25 px-3 py-1 rounded-full">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                  <span>100% IN-BROWSER WORKER</span>
                  <span className="text-slate-500">|</span>
                  <span>0 SOURCE BYTES UPLOADED</span>
                </div>

                {/* Air-Gapped Mode Toggle */}
                <label className="inline-flex items-center gap-2 text-xs font-mono text-slate-300 bg-white/[0.03] border border-white/10 hover:border-cyan-400/30 px-2.5 py-1 rounded-full cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={offlineMode}
                    onChange={(e) => setOfflineMode(e.target.checked)}
                    className="accent-cyan-400 rounded cursor-pointer"
                  />
                  <span>Air-Gapped Mode</span>
                </label>
              </div>

              <h1 className="text-2xl sm:text-4xl font-extrabold tracking-tight text-white leading-[1.15]">
                Catch Leaked Keys, Malware Packages &amp; AI Hallucinations{' '}
                <span className="bg-gradient-to-r from-cyan-300 via-sky-300 to-emerald-300 bg-clip-text text-transparent">
                  Before You Push.
                </span>
              </h1>

              <p className="text-sm sm:text-[15px] text-slate-300/90 leading-relaxed">
                Drop any project folder or scan via CLI. RepoXray detects{' '}
                <span className="text-white font-medium">OSV vulnerabilities</span>,{' '}
                <span className="text-white font-medium">
                  npm 0.0.1-security malware tombstones
                </span>
                , <span className="text-white font-medium">AI slopsquatting</span>, and{' '}
                <span className="text-white font-medium">exposed .env &amp; MCP credentials</span>
                —then compiles deterministic{' '}
                <code className="text-cyan-300 text-xs bg-cyan-500/10 px-1.5 py-0.5 rounded">
                  AGENTS.md
                </code>{' '}
                +{' '}
                <code className="text-cyan-300 text-xs bg-cyan-500/10 px-1.5 py-0.5 rounded">
                  .aiignore
                </code>{' '}
                shields in under 2 seconds.
              </p>
            </div>

            <div className="mt-6 pt-5 border-t border-white/10 space-y-3">
              {/* Mobile-first CTA order: Instant Demo on top on narrow screens, side-by-side on desktop */}
              <div className="flex flex-col-reverse sm:flex-row sm:flex-wrap items-stretch sm:items-center gap-3">
                <button
                  type="button"
                  disabled={isScanning}
                  onClick={handleBrowseLocalFolder}
                  className="px-4 py-2.5 rounded-lg bg-emerald-400 hover:bg-emerald-300 disabled:opacity-50 text-slate-950 font-semibold text-sm shadow-[0_0_24px_-6px_rgba(52,211,153,0.5)] transition cursor-pointer text-center"
                >
                  Select Local Project Folder
                </button>

                <button
                  type="button"
                  disabled={isScanning}
                  onClick={handleDemoScan}
                  className="px-4 py-2.5 rounded-lg bg-white/[0.06] hover:bg-white/[0.11] border border-cyan-400/35 text-cyan-200 font-medium text-sm transition cursor-pointer text-center"
                >
                  Run Instant Vulnerable Demo (1s)
                </button>

                <span className="text-xs text-slate-500 font-mono ml-auto hidden xl:inline">
                  Drag &amp; drop folder anywhere here
                </span>
              </div>

              <p className="text-[11px] font-mono text-slate-400/90">
                {offlineMode
                  ? 'Air-Gapped active: 0 outbound network requests. Pure static, secret & token telemetry.'
                  : 'Privacy: Source files stay in local RAM. Only package names/versions query OSV.dev & npmjs.org.'}
              </p>
            </div>
          </div>

          {/* Right: Public GitHub URL X-Ray + CLI */}
          <div className="relative overflow-hidden lg:col-span-5 rounded-2xl rx-bento-card p-6 flex flex-col justify-between space-y-5">
            <div
              aria-hidden="true"
              className="pointer-events-none absolute inset-x-10 top-0 h-px bg-gradient-to-r from-transparent via-emerald-400/40 to-transparent"
            />

            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono uppercase tracking-wider text-cyan-300/90">
                  Remote Public Repository X-Ray
                </span>
                <span className="text-[11px] font-mono text-slate-500">5m session cache</span>
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
                  aria-label="GitHub repository owner/repo or URL"
                  className="w-full px-3.5 py-2.5 rounded-lg bg-black/50 border border-white/10 focus:border-cyan-400 focus:outline-none text-sm font-mono text-slate-100 placeholder:text-slate-600 transition"
                />
                <button
                  type="submit"
                  disabled={isScanning || !githubInput.trim()}
                  className="w-full py-2.5 rounded-lg bg-cyan-400 hover:bg-cyan-300 disabled:opacity-40 text-slate-950 font-semibold text-sm shadow-[0_0_24px_-6px_rgba(34,211,238,0.45)] transition cursor-pointer"
                >
                  {isScanning ? 'Scanning Repository...' : 'X-Ray GitHub Repository'}
                </button>
              </form>

              <div className="flex flex-wrap items-center gap-1.5 pt-1">
                <span className="text-xs text-slate-500 mr-1">Instant presets:</span>
                {['Ra9mirez11/repoxray', 'expressjs/express', 'colinhacks/zod'].map((sample) => (
                  <button
                    key={sample}
                    type="button"
                    disabled={isScanning}
                    onClick={() => {
                      setGithubInput(sample);
                      void handleGitHubScan(sample);
                    }}
                    className="text-xs font-mono px-2 py-0.5 rounded bg-white/[0.04] hover:bg-white/[0.09] text-slate-300 border border-white/10 transition cursor-pointer"
                  >
                    {sample}
                  </button>
                ))}
              </div>
            </div>

            <div className="pt-4 border-t border-white/10 space-y-2.5">
              <div className="text-xs text-slate-400 flex items-center justify-between">
                <span>Zero-Install CLI &amp; Git Pre-Commit Gate:</span>
                <span className="font-mono text-[11px] text-emerald-400">0 runtime deps</span>
              </div>
              <div className="flex items-center justify-between px-3 py-2 rounded-lg bg-black/50 border border-white/10 font-mono text-xs text-slate-200">
                <span className="truncate mr-2">npx rxray . --write-shield</span>
                <button
                  type="button"
                  onClick={() => triggerCopy('hero-cli', 'npx rxray . --write-shield')}
                  className="text-cyan-400 hover:text-cyan-300 font-sans font-semibold shrink-0 cursor-pointer"
                >
                  {copiedKey === 'hero-cli' ? 'COPIED' : 'COPY'}
                </button>
              </div>
              <div className="flex items-center justify-between px-3 py-2 rounded-lg bg-black/50 border border-white/10 font-mono text-xs text-slate-300">
                <span className="truncate mr-2">npx rxray init-hook</span>
                <button
                  type="button"
                  onClick={() => triggerCopy('hook-cli', 'npx rxray init-hook')}
                  className="text-emerald-400 hover:text-emerald-300 font-sans font-semibold shrink-0 cursor-pointer"
                >
                  {copiedKey === 'hook-cli' ? 'COPIED' : 'COPY'}
                </button>
              </div>
            </div>
          </div>
        </section>

        {/* Progress / Error Banner */}
        {isScanning && (
          <div className="rounded-xl border border-cyan-400/40 bg-cyan-500/10 backdrop-blur-md px-4 py-3 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-ping" />
              <span className="text-sm font-mono text-cyan-200">
                {progressText || 'Running off-main-thread static & registry telemetry...'}
              </span>
            </div>
            <span className="text-xs font-mono text-cyan-300 hidden sm:inline">
              WEB WORKER ISOLATED
            </span>
          </div>
        )}

        {errorMsg && (
          <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 backdrop-blur-md px-4 py-3 text-sm text-rose-200 font-mono">
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
                    className={`lg:col-span-4 rounded-2xl border ${theme.border} ${theme.glow} bg-[#080d18]/90 backdrop-blur-md p-5 flex items-center gap-5`}
                  >
                    <div className="relative w-28 h-28 shrink-0 flex items-center justify-center">
                      <svg className="w-28 h-28 -rotate-90" viewBox="0 0 108 108">
                        <circle
                          cx="54"
                          cy="54"
                          r={radius}
                          className="stroke-slate-800/90"
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
                      <div
                        className="text-lg font-bold text-white truncate"
                        title={report.projectName}
                      >
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
                      className="rounded-2xl rx-bento-card p-4 flex flex-col justify-between"
                    >
                      <div className="text-xs font-mono text-slate-400">{pillar.label}</div>
                      <div className="my-2 text-2xl font-bold font-mono text-white">
                        {pillar.score}
                        <span className="text-xs text-slate-500 font-normal">/100</span>
                      </div>
                      <div className="space-y-1.5">
                        <div className="w-full h-1.5 bg-white/10 rounded-full overflow-hidden">
                          <div
                            className={`h-full ${barColor} transition-all duration-300`}
                            style={{ width: `${pillar.score}%` }}
                          />
                        </div>
                        <div className="text-[11px] text-slate-400 truncate">{pillar.sub}</div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Primary Action Tab Bar */}
            <div className="border-b border-white/10 flex flex-wrap gap-2">
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
                      ? 'border-cyan-400 text-cyan-300 bg-cyan-500/10 rounded-t-lg'
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
                        className={`px-3 py-1 rounded-full text-xs font-mono border transition cursor-pointer ${
                          categoryFilter === pill.id
                            ? 'bg-cyan-500/15 border-cyan-400/50 text-cyan-300'
                            : 'bg-white/[0.03] border-white/10 text-slate-400 hover:text-slate-200'
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
                      className="px-3.5 py-1.5 rounded-lg bg-emerald-500/15 border border-emerald-400/40 text-emerald-300 hover:bg-emerald-500/25 text-xs font-semibold transition cursor-pointer"
                    >
                      Generate 1-Click AI Fix Prompt -&gt;
                    </button>
                  )}
                </div>

                {filteredFindings.length === 0 ? (
                  <div className="rounded-2xl border border-emerald-500/30 bg-emerald-500/5 p-8 text-center space-y-2">
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
                        className="rounded-2xl rx-bento-card p-4 sm:p-5 space-y-2.5"
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
                            <span className="px-2 py-0.5 rounded bg-black/50 border border-white/10 text-cyan-300">
                              {f.line ? `${f.file}:${f.line}` : f.file}
                            </span>
                            <span className="text-slate-500">{f.ruleId}</span>
                          </div>
                        </div>

                        <p className="text-sm text-slate-300">{f.description}</p>

                        {f.evidence && (
                          <div className="px-3 py-2 rounded-lg bg-black/60 border border-white/10 font-mono text-xs text-amber-300 overflow-x-auto">
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
              <div className="rounded-2xl rx-bento-card p-5 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <h3 className="text-base font-semibold text-white">
                      Bring-Your-Own-Agent Remediation Prompt ($0 API Token Cost)
                    </h3>
                    <p className="text-xs text-slate-400">
                      Hardened with untrusted-input XML sandboxing. Paste into Cursor, Claude Code,
                      Antigravity, Windsurf, or ChatGPT to patch every finding safely.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => triggerCopy('fix-prompt', compiled.fixPrompt)}
                    className="px-4 py-2 rounded-lg bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-semibold text-xs shadow-[0_0_20px_-5px_rgba(34,211,238,0.5)] transition cursor-pointer"
                  >
                    {copiedKey === 'fix-prompt' ? 'COPIED TO CLIPBOARD' : 'Copy Full Fix Prompt'}
                  </button>
                </div>

                {/* High-Conversion Post-Value Reciprocity Trigger */}
                {hasCopiedFixPrompt && (
                  <div className="rounded-xl border border-emerald-400/35 bg-gradient-to-r from-emerald-500/10 via-cyan-500/10 to-transparent p-3.5 flex flex-wrap items-center justify-between gap-3">
                    <div className="text-xs text-slate-200">
                      <span className="font-semibold text-emerald-300 mr-1.5">
                        Remediation prompt ready.
                      </span>
                      If RepoXray just saved you manual audit time, star the open-source engine or
                      back new supply-chain signatures.
                    </div>
                    <div className="flex items-center gap-2">
                      <a
                        href="https://github.com/Ra9mirez11/repoxray"
                        target="_blank"
                        rel="noreferrer"
                        className="px-3 py-1.5 rounded-md bg-white/10 hover:bg-white/15 border border-white/15 text-xs font-semibold text-white transition"
                      >
                        Star on GitHub
                      </a>
                      <a
                        href="https://github.com/sponsors/Ra9mirez11"
                        target="_blank"
                        rel="noreferrer"
                        className="px-3 py-1.5 rounded-md bg-emerald-400 hover:bg-emerald-300 text-xs font-semibold text-slate-950 transition"
                      >
                        Sponsor Research
                      </a>
                    </div>
                  </div>
                )}

                <pre className="p-4 rounded-xl bg-black/60 border border-white/10 text-xs font-mono text-slate-200 overflow-x-auto whitespace-pre-wrap max-h-[480px] overflow-y-auto">
                  {compiled.fixPrompt}
                </pre>
              </div>
            )}

            {/* TAB 3: COMPILED GUARDRAILS */}
            {activeTab === 'guardrails' && (
              <div className="rounded-2xl rx-bento-card p-5 space-y-4">
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
                        className={`px-3 py-1.5 rounded-md text-xs font-mono border transition cursor-pointer ${
                          guardrailDoc === doc.id
                            ? 'bg-cyan-500/15 border-cyan-400/50 text-cyan-300'
                            : 'bg-black/50 border-white/10 text-slate-400 hover:text-slate-200'
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
                            className="px-3.5 py-1.5 rounded-md bg-white/[0.06] hover:bg-white/[0.12] border border-white/10 text-xs font-semibold text-slate-100 cursor-pointer"
                          >
                            {copiedKey === `doc-${guardrailDoc}` ? 'COPIED' : 'Copy'}
                          </button>
                          <button
                            type="button"
                            onClick={() => downloadBlob(activeFilename, activeContent)}
                            className="px-3.5 py-1.5 rounded-md bg-emerald-400 hover:bg-emerald-300 text-xs font-semibold text-slate-950 cursor-pointer"
                          >
                            Download {activeFilename}
                          </button>
                        </>
                      );
                    })()}
                  </div>
                </div>

                <pre className="p-4 rounded-xl bg-black/60 border border-white/10 text-xs font-mono text-slate-200 overflow-x-auto whitespace-pre-wrap max-h-[460px] overflow-y-auto">
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
              <div className="rounded-2xl rx-bento-card p-5 space-y-4">
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
                        className="p-3 rounded-xl bg-black/50 border border-white/10 space-y-1.5"
                      >
                        <div className="flex items-center justify-between text-xs font-mono">
                          <span className="text-slate-200 truncate">{tf.path}</span>
                          <span className={tf.isBloat ? 'text-amber-400' : 'text-cyan-400'}>
                            {tf.tokens.toLocaleString()} tokens ({(tf.bytes / 1024).toFixed(1)} KB)
                          </span>
                        </div>
                        <div className="w-full h-1.5 bg-white/5 rounded-full overflow-hidden">
                          <div
                            className={`h-full ${tf.isBloat ? 'bg-amber-400' : 'bg-cyan-400'}`}
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
                <div className="rounded-2xl rx-bento-card p-5 space-y-5">
                  <div className="space-y-2">
                    <h3 className="text-base font-semibold text-white">
                      GitHub README Security Badge
                    </h3>
                    <p className="text-xs text-slate-400">
                      Add your verified RepoXray score badge to your repository README to prove
                      supply-chain and secret hygiene.
                    </p>
                    <div className="p-4 rounded-xl bg-black/60 border border-white/10 flex items-center justify-between gap-4">
                      <img
                        src={`data:image/svg+xml;utf8,${encodeURIComponent(compiled.badgeSvg)}`}
                        alt="RepoXray Security Badge"
                        width="196"
                        height="22"
                        className="h-[22px] w-auto"
                      />
                      <span className="text-xs font-mono text-slate-500">Live SVG Preview</span>
                    </div>
                    <div className="flex flex-wrap gap-2 pt-1">
                      <button
                        type="button"
                        onClick={() => triggerCopy('badge-md', compiled.badgeMarkdown)}
                        className="px-3 py-1.5 rounded-md bg-cyan-400 hover:bg-cyan-300 text-slate-950 text-xs font-semibold cursor-pointer"
                      >
                        {copiedKey === 'badge-md' ? 'COPIED MARKDOWN' : 'Copy README Markdown'}
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          downloadBlob('repoxray-badge.svg', compiled.badgeSvg, 'image/svg+xml')
                        }
                        className="px-3 py-1.5 rounded-md bg-white/[0.06] hover:bg-white/[0.12] border border-white/10 text-slate-200 text-xs font-semibold cursor-pointer"
                      >
                        Download Badge .SVG
                      </button>
                    </div>
                  </div>

                  <div className="pt-4 border-t border-white/10 space-y-2">
                    <h4 className="text-sm font-semibold text-white">
                      Share Scorecard &amp; Export Audit Report
                    </h4>
                    <pre className="p-3 rounded-xl bg-black/60 border border-white/10 text-xs font-mono text-slate-300 whitespace-pre-wrap">
                      {compiled.shareSummary}
                    </pre>
                    <div className="flex flex-wrap gap-2">
                      <button
                        type="button"
                        onClick={() => triggerCopy('share-post', compiled.shareSummary)}
                        className="px-3 py-1.5 rounded-md bg-white/[0.06] hover:bg-white/[0.12] border border-white/10 text-xs font-semibold text-slate-100 cursor-pointer"
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
                        className="px-3 py-1.5 rounded-md bg-white/[0.06] hover:bg-white/[0.12] border border-white/10 text-xs font-semibold text-slate-100 cursor-pointer"
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
                        className="px-3 py-1.5 rounded-md bg-white/[0.06] hover:bg-white/[0.12] border border-white/10 text-xs font-semibold text-slate-100 cursor-pointer"
                      >
                        Export JSON (CI / SOC2)
                      </button>
                    </div>
                  </div>
                </div>

                {/* Right: GitHub Actions CI Gate + Sponsorship */}
                <div className="rounded-2xl rx-bento-card p-5 space-y-5">
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <h3 className="text-base font-semibold text-white">
                        1-Line GitHub Actions Pull Request Gate
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
                    <pre className="p-3 rounded-xl bg-black/60 border border-white/10 text-xs font-mono text-slate-300 overflow-x-auto">
                      {GITHUB_ACTION_YAML}
                    </pre>
                  </div>

                  <div className="p-4 rounded-xl border border-cyan-400/25 bg-cyan-500/[0.06] space-y-2">
                    <div className="text-xs font-mono uppercase text-cyan-300">
                      Open-Core Sustainability &amp; Security Audits
                    </div>
                    <div className="text-sm font-semibold text-white">
                      Back RepoXray Development or Request Written Repo Audits
                    </div>
                    <p className="text-xs text-slate-300/90 leading-relaxed">
                      RepoXray is MIT-licensed and free for developers. Engineering teams can back
                      continuous detection rules or commission written supply-chain &amp; repository
                      security audits via{' '}
                      <a
                        href="https://github.com/sponsors/Ra9mirez11"
                        target="_blank"
                        rel="noreferrer"
                        className="text-cyan-300 underline hover:text-cyan-200"
                      >
                        GitHub Sponsors
                      </a>
                      .
                    </p>
                  </div>
                </div>
              </div>
            )}
          </section>
        )}

        {/* Bento Architecture, Telemetry Capabilities & Protected Community Contributor Showcase */}
        <section aria-label="Detection Architecture and Research Credits" className="space-y-4 pt-2">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h2 className="text-xs font-mono uppercase tracking-widest text-slate-400">
              4-Pillar Isomorphic Detection Architecture &amp; Community Research
            </h2>
            <span className="text-xs font-mono text-slate-500">
              Same core engine in Browser Worker &amp; ~19 KB CLI
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-12 gap-4">
            {/* Bento 1: Slopsquatting & Tombstones */}
            <div className="md:col-span-4 rounded-2xl rx-bento-card p-5 space-y-2.5">
              <div className="inline-flex items-center gap-2 text-[11px] font-mono text-cyan-300 bg-cyan-500/10 border border-cyan-400/20 px-2.5 py-0.5 rounded-full">
                SUPPLY-CHAIN &amp; MCP
              </div>
              <h3 className="text-base font-semibold text-white">
                Anti-Slopsquatting &amp; Malware Tombstones
              </h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Cross-checks <code className="text-slate-200">package.json</code>,{' '}
                <code className="text-slate-200">package-lock.json</code>,{' '}
                <code className="text-slate-200">requirements.txt</code>,{' '}
                <code className="text-slate-200">Cargo.toml</code>, and{' '}
                <code className="text-slate-200">.mcp.json</code> against OSV.dev CVEs, unregistered
                404 takeover slots, newly published packages (&lt;21d), and{' '}
                <code className="text-amber-300">0.0.1-security</code> takedowns.
              </p>
            </div>

            {/* Bento 2: Secret Entropy & Code Sinks */}
            <div className="md:col-span-4 rounded-2xl rx-bento-card p-5 space-y-2.5">
              <div className="inline-flex items-center gap-2 text-[11px] font-mono text-emerald-300 bg-emerald-500/10 border border-emerald-400/20 px-2.5 py-0.5 rounded-full">
                SECRETS &amp; SAST SINKS
              </div>
              <h3 className="text-base font-semibold text-white">
                Shannon Entropy + Auto-Redacted Evidence
              </h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Detects AWS, GitHub PAT, OpenAI/Anthropic, Stripe Live, Slack, private keys, and DB
                URIs alongside SQL template injection, shell interpolation, and dynamic{' '}
                <code className="text-slate-200">eval</code>—automatically masking every secret
                before rendering or prompt export.
              </p>
            </div>

            {/* Bento 3: Protected Community Security Research Contributor Card (@X1Y1) */}
            <div className="md:col-span-4 rounded-2xl rx-bento-card p-5 space-y-2.5 border-cyan-400/20">
              <div className="flex items-center justify-between gap-2">
                <span className="inline-flex items-center gap-1.5 text-[11px] font-mono text-amber-300 bg-amber-500/10 border border-amber-400/25 px-2.5 py-0.5 rounded-full">
                  <svg className="w-3 h-3" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M12 2l2.9 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l7.1-1.01L12 2z" />
                  </svg>
                  SECURITY RESEARCH CREDIT
                </span>
                <span className="text-xs font-mono font-bold text-cyan-300">@X1Y1</span>
              </div>
              <h3 className="text-base font-semibold text-white">
                Empirical MCP Telemetry Contributor
              </h3>
              <p className="text-xs text-slate-300/90 leading-relaxed">
                Special thanks to <span className="text-white font-semibold">@X1Y1</span> for
                contributing empirical security findings from auditing{' '}
                <span className="text-cyan-300 font-mono">10,659</span> public MCP configurations—powering
                RepoXray&apos;s <code className="text-slate-200">0.0.1-security</code> tombstone,{' '}
                <code className="text-slate-200">uvx</code> wrong-registry, vendor scope
                impersonation (<code className="text-slate-200">@anthropic/*</code>), unpinned Git
                MCP installs, and <code className="text-slate-200">env</code> block credential
                rules.
              </p>
            </div>
          </div>
        </section>
      </main>

      <footer className="relative z-10 border-t border-white/10 bg-[#04070d]/90 py-6 mt-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 space-y-2 text-center">
          <div className="text-xs font-mono text-slate-400">
            RepoXray Engine v0.3.2 — 100% Client-Side Web Worker Execution | Powered by OSV.dev &amp;
            Public Registry Telemetry | CLI: <code className="text-cyan-300">npx rxray</code>
          </div>
          <p className="text-[11px] text-slate-500 max-w-3xl mx-auto leading-relaxed">
            Legal Notice: RepoXray performs automated static pattern and public package-registry
            heuristic analysis. Provided &quot;AS IS&quot; under the MIT License without warranty of
            any kind; scores do not constitute formal security certification or replace manual
            penetration testing.
          </p>
        </div>
      </footer>
    </div>
  );
}
