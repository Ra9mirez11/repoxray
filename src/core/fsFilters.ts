export const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  'dist-web',
  'dist-cli',
  'build',
  '.next',
  'coverage',
  'target',
  '.venv',
  'venv',
  '__pycache__',
  'vendor',
]);

export const IGNORED_PATH_PREFIXES = Array.from(SKIP_DIRS).map((d) => `${d}/`);

export const BINARY_EXTENSIONS = new Set([
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.webp',
  '.ico',
  '.pdf',
  '.zip',
  '.tar',
  '.gz',
  '.7z',
  '.exe',
  '.dll',
  '.so',
  '.dylib',
  '.wasm',
  '.woff',
  '.woff2',
  '.ttf',
  '.otf',
  '.mp3',
  '.mp4',
  '.mov',
  '.pyc',
  '.lockb',
]);

export function isBinaryFileName(pathOrName: string): boolean {
  const lower = pathOrName.toLowerCase();
  const dot = lower.lastIndexOf('.');
  if (dot < 0) return false;
  return BINARY_EXTENSIONS.has(lower.slice(dot));
}
