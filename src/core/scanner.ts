import { analyzeContextAndCode } from './contextAnalyzer';
import { scanSecretsAndExposure } from './secretScanner';
import { auditSupplyChainLive, extractDependencies } from './supplyChain';
import type {
  Finding,
  FindingCategory,
  Grade,
  ScanOptions,
  ScanReport,
  Severity,
  VirtualFile,
} from './types';

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const PENALTY_BY_SEVERITY: Record<Severity, number> = {
  critical: 28,
  high: 15,
  medium: 7,
  low: 3,
  info: 0,
};

function computeCategoryScore(findings: Finding[], category: FindingCategory): number {
  const relevant = findings.filter((f) => f.category === category);
  let deduction = 0;
  for (const f of relevant) {
    deduction += PENALTY_BY_SEVERITY[f.severity];
  }
  return Math.max(0, 100 - deduction);
}

export function scoreToGrade(score: number, hasCritical: boolean): Grade {
  if (hasCritical && score >= 75) return 'C';
  if (score >= 95) return 'A+';
  if (score >= 85) return 'A';
  if (score >= 72) return 'B';
  if (score >= 58) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

function inferProjectName(files: VirtualFile[], explicitName?: string): string {
  if (explicitName && explicitName.trim()) return explicitName.trim();
  const pkgJson = files.find((f) => f.path === 'package.json');
  if (pkgJson) {
    try {
      const parsed = JSON.parse(pkgJson.content) as { name?: string };
      if (parsed.name) return parsed.name;
    } catch {
      // ignore
    }
  }
  return 'local-repository';
}

export async function runRepoXray(
  rawFiles: VirtualFile[],
  options: ScanOptions = {},
): Promise<ScanReport> {
  const start = performance.now();
  const files = rawFiles.map((f) => ({
    ...f,
    path: f.path.replace(/\\/g, '/').replace(/^\/+/, ''),
  }));

  options.onProgress?.('Scanning secrets, .env hygiene & MCP configurations...');
  const secretFindings = scanSecretsAndExposure(files);

  options.onProgress?.('Extracting dependency manifests & lifecycle hooks...');
  const { dependencies, scriptFindings } = extractDependencies(files);

  options.onProgress?.(
    options.offline
      ? 'Analyzing dependency tree (offline mode)...'
      : 'Querying OSV.dev & npm registry for CVEs and slopsquatting...',
  );
  const { packageHealth, findings: liveSupplyFindings } = await auditSupplyChainLive(
    dependencies,
    options.offline ?? false,
  );

  options.onProgress?.('Mapping AI token footprint & static code safety...');
  const contextResult = analyzeContextAndCode(files);

  const allFindings = [
    ...secretFindings,
    ...scriptFindings,
    ...liveSupplyFindings,
    ...contextResult.findings,
  ].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  const subScores = {
    supplyChain: computeCategoryScore(allFindings, 'supply-chain'),
    secrets: computeCategoryScore(allFindings, 'secrets'),
    codeSafety: computeCategoryScore(allFindings, 'code-safety'),
    aiReadiness: computeCategoryScore(allFindings, 'ai-context'),
  };

  // Weighted composite score (Supply Chain 30%, Secrets 35%, Code Safety 20%, AI Readiness 15%)
  const weighted = Math.round(
    subScores.supplyChain * 0.3 +
      subScores.secrets * 0.35 +
      subScores.codeSafety * 0.2 +
      subScores.aiReadiness * 0.15,
  );

  const hasCritical = allFindings.some((f) => f.severity === 'critical');
  const finalScore = hasCritical ? Math.min(weighted, 68) : weighted;
  const grade = scoreToGrade(finalScore, hasCritical);

  const durationMs = Math.max(1, Math.round(performance.now() - start));

  return {
    projectName: inferProjectName(files, options.projectName),
    scannedAt: new Date().toISOString(),
    durationMs,
    score: finalScore,
    grade,
    subScores,
    totalFiles: files.length,
    totalBytes: contextResult.totalBytes,
    totalTokens: contextResult.totalTokens,
    optimizableTokens: contextResult.optimizableTokens,
    tokenSavingsPercent: contextResult.tokenSavingsPercent,
    dependencies,
    packageHealth,
    topTokenFiles: contextResult.topTokenFiles,
    stack: contextResult.stack,
    findings: allFindings,
  };
}
