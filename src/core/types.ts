export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type FindingCategory =
  | 'supply-chain'
  | 'secrets'
  | 'code-safety'
  | 'ai-context';

export type Grade = 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';

export interface VirtualFile {
  /** Normalized forward-slash relative path, e.g. "src/index.ts" */
  path: string;
  content: string;
  sizeBytes?: number;
}

export interface Finding {
  id: string;
  ruleId: string;
  category: FindingCategory;
  severity: Severity;
  title: string;
  description: string;
  file: string;
  line?: number;
  evidence?: string;
  remediation: string;
  referenceUrl?: string;
}

export type Ecosystem = 'npm' | 'PyPI' | 'crates.io';

export interface DependencyRecord {
  name: string;
  versionSpec: string;
  resolvedVersion: string;
  ecosystem: Ecosystem;
  manifestPath: string;
  isDev: boolean;
}

export interface PackageHealth {
  name: string;
  ecosystem: Ecosystem;
  existsInRegistry: boolean;
  createdAt?: string;
  ageDays?: number;
  hasInstallScript?: boolean;
  installScriptSnippet?: string;
  vulnerabilities: Array<{
    id: string;
    summary: string;
    severity: Severity;
    url: string;
  }>;
}

export interface TokenFileStat {
  path: string;
  bytes: number;
  tokens: number;
  isBloat: boolean;
  bloatReason?: string;
}

export interface SubScores {
  supplyChain: number;
  secrets: number;
  codeSafety: number;
  aiReadiness: number;
}

export interface DetectedStack {
  languages: string[];
  frameworks: string[];
  packageManagers: string[];
  topDirectories: string[];
  hasGitignore: boolean;
  hasAiIgnore: boolean;
  hasAgentsMd: boolean;
  hasMcpConfig: boolean;
}

export interface ScanOptions {
  projectName?: string;
  offline?: boolean;
  onProgress?: (stage: string) => void;
}

export interface ScanReport {
  projectName: string;
  scannedAt: string;
  durationMs: number;
  score: number;
  grade: Grade;
  subScores: SubScores;
  totalFiles: number;
  totalBytes: number;
  totalTokens: number;
  optimizableTokens: number;
  tokenSavingsPercent: number;
  dependencies: DependencyRecord[];
  packageHealth: PackageHealth[];
  topTokenFiles: TokenFileStat[];
  stack: DetectedStack;
  findings: Finding[];
}

export interface CompiledShield {
  fixPrompt: string;
  agentsMd: string;
  cursorRules: string;
  aiIgnore: string;
  badgeSvg: string;
  badgeMarkdown: string;
  shareSummary: string;
  prCommentMarkdown: string;
  markdownReport: string;
}
