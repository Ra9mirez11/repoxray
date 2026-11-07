import { build } from 'esbuild';
import { mkdir, chmod } from 'node:fs/promises';

await mkdir('dist-cli', { recursive: true });

await build({
  entryPoints: ['src/cli/index.ts'],
  outfile: 'dist-cli/cli.mjs',
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node18',
  minify: true,
  banner: {
    js: '#!/usr/bin/env node',
  },
});

try {
  await chmod('dist-cli/cli.mjs', 0o755);
} catch {
  // Windows ignores POSIX chmod bits; safe to ignore.
}

console.log('CLI bundle created at dist-cli/cli.mjs');
