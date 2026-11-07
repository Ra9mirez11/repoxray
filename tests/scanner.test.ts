import { describe, expect, it } from 'vitest';
import { compileShield } from '../src/core/compiler';
import { buildVulnerableDemoRepo } from '../src/core/demoPreset';
import { runRepoXray } from '../src/core/scanner';
import { redactSecret } from '../src/core/secretScanner';

describe('RepoXray Core Engine', () => {
  it('redacts sensitive tokens safely without exposing middle characters', () => {
    const sample = ['sk-proj-', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ123456'].join('');
    const redacted = redactSecret(sample);
    expect(redacted).toContain('sk-pr****');
    expect(redacted).not.toContain('GHIJKLMNOP');
  });

  it('detects secrets, MCP risks, postinstall hooks, SQLi, eval, and context bloat on demo repo', async () => {
    const demoFiles = buildVulnerableDemoRepo();
    const report = await runRepoXray(demoFiles, {
      projectName: 'demo-vulnerable-app',
      offline: true,
    });

    expect(report.score).toBeLessThan(70);
    expect(['D', 'F', 'C']).toContain(report.grade);

    const ruleIds = new Set(report.findings.map((f) => f.ruleId));
    expect(ruleIds.has('SC-MALICIOUS-LIFECYCLE-HOOK')).toBe(true);
    expect(ruleIds.has('SEC-GITIGNORE-ENV')).toBe(true);
    expect(ruleIds.has('SEC-PLAINTEXT-ENV-EXPOSED')).toBe(true);
    expect(ruleIds.has('SEC-MCP-UNPINNED-NPX')).toBe(true);
    expect(ruleIds.has('SEC-MCP-PLAINTEXT-ENV')).toBe(true);
    expect(ruleIds.has('SEC-AWS-KEY')).toBe(true);
    expect(ruleIds.has('CODE-SQL-TEMPLATE-INJECTION')).toBe(true);
    expect(ruleIds.has('CODE-DYNAMIC-EVAL')).toBe(true);
    expect(ruleIds.has('AI-MISSING-AIIGNORE')).toBe(true);

    const compiled = compileShield(report);
    expect(compiled.fixPrompt).toContain('Required Fixes');
    expect(compiled.aiIgnore).toContain('package-lock.json');
    expect(compiled.agentsMd).toContain('AGENTS.md');
    expect(compiled.badgeSvg).toContain('<svg');
  });

  it('scores a clean, properly shielded repository as Grade A+ (100/100)', async () => {
    const cleanRepo = [
      {
        path: 'package.json',
        content: JSON.stringify({
          name: 'clean-service',
          version: '1.0.0',
          dependencies: { zod: '3.24.2' },
        }),
      },
      {
        path: '.gitignore',
        content: 'node_modules/\n.env\n.env.*\n',
      },
      {
        path: '.aiignore',
        content: '.env\n.env.*\npackage-lock.json\n',
      },
      {
        path: 'AGENTS.md',
        content: '# Guardrails\n',
      },
      {
        path: 'src/index.ts',
        content: 'export function add(a: number, b: number): number { return a + b; }\n',
      },
    ];

    const report = await runRepoXray(cleanRepo, {
      projectName: 'clean-service',
      offline: true,
    });

    expect(report.findings).toHaveLength(0);
    expect(report.score).toBe(100);
    expect(report.grade).toBe('A+');
  });

  it('prefers exact locked versions from package-lock.json over loose semver ranges', async () => {
    const repoWithLock = [
      {
        path: 'package.json',
        content: JSON.stringify({
          name: 'locked-app',
          devDependencies: { vite: '^6.0.0' },
        }),
      },
      {
        path: 'package-lock.json',
        content: JSON.stringify({
          name: 'locked-app',
          lockfileVersion: 3,
          packages: {
            'node_modules/vite': { version: '6.4.5' },
          },
        }),
      },
      { path: '.gitignore', content: '.env\n.env.*\n' },
      { path: '.aiignore', content: '.env\npackage-lock.json\n' },
      { path: 'AGENTS.md', content: '# Rules\n' },
    ];

    const report = await runRepoXray(repoWithLock, { offline: true });
    expect(report.dependencies[0]?.resolvedVersion).toBe('6.4.5');
    expect(report.score).toBe(100);
  });
});
