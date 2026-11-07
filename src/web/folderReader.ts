import type { VirtualFile } from '../core/types';

const SKIP_DIRS = new Set([
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
]);

const BINARY_EXTS = new Set([
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
  '.pyc',
  '.lockb',
]);

function isBinaryName(name: string): boolean {
  const dot = name.lastIndexOf('.');
  if (dot < 0) return false;
  return BINARY_EXTS.has(name.slice(dot).toLowerCase());
}

async function fileObjToVirtual(file: File, relPath: string): Promise<VirtualFile | null> {
  const normalized = relPath.replace(/\\/g, '/').replace(/^\/+/, '');
  const segments = normalized.split('/');
  if (segments.some((s) => SKIP_DIRS.has(s))) return null;
  const baseName = segments[segments.length - 1] ?? normalized;
  if (isBinaryName(baseName)) return null;

  if (file.size > 300_000) {
    return {
      path: normalized,
      content: '',
      sizeBytes: file.size,
    };
  }

  const content = await file.text();
  return {
    path: normalized,
    content,
    sizeBytes: file.size,
  };
}

/** Reads directory via File System Access API (Chrome / Edge / Brave / Opera) */
export async function pickDirectoryNative(): Promise<{
  projectName: string;
  files: VirtualFile[];
} | null> {
  const win = window as unknown as {
    showDirectoryPicker?: () => Promise<FileSystemDirectoryHandle>;
  };
  if (typeof win.showDirectoryPicker !== 'function') {
    return null;
  }

  const rootHandle = await win.showDirectoryPicker();
  const files: VirtualFile[] = [];

  async function traverse(dirHandle: FileSystemDirectoryHandle, prefix: string): Promise<void> {
    const iterable = dirHandle as unknown as AsyncIterable<[string, FileSystemHandle]>;
    for await (const [name, handle] of iterable) {
      if (handle.kind === 'directory') {
        if (SKIP_DIRS.has(name)) continue;
        await traverse(
          handle as FileSystemDirectoryHandle,
          prefix ? `${prefix}/${name}` : name,
        );
      } else if (handle.kind === 'file') {
        if (isBinaryName(name)) continue;
        const f = await (handle as FileSystemFileHandle).getFile();
        const rel = prefix ? `${prefix}/${name}` : name;
        const vf = await fileObjToVirtual(f, rel);
        if (vf) files.push(vf);
      }
    }
  }

  await traverse(rootHandle, '');
  return {
    projectName: rootHandle.name,
    files,
  };
}

/** Reads FileList from <input type="file" webkitdirectory /> fallback */
export async function readFileListFromInput(fileList: FileList): Promise<{
  projectName: string;
  files: VirtualFile[];
}> {
  const files: VirtualFile[] = [];
  let rootName = 'local-folder';

  for (let i = 0; i < fileList.length; i++) {
    const f = fileList[i];
    const rawRel = (f as File & { webkitRelativePath?: string }).webkitRelativePath || f.name;
    const parts = rawRel.split('/');
    if (parts.length > 1 && rootName === 'local-folder') {
      rootName = parts[0];
    }
    const stripped = parts.length > 1 ? parts.slice(1).join('/') : rawRel;
    const vf = await fileObjToVirtual(f, stripped);
    if (vf) files.push(vf);
  }

  return { projectName: rootName, files };
}

interface WebkitEntry {
  isFile: boolean;
  isDirectory: boolean;
  name: string;
  file?: (cb: (f: File) => void, err?: (e: unknown) => void) => void;
  createReader?: () => {
    readEntries: (cb: (entries: WebkitEntry[]) => void, err?: (e: unknown) => void) => void;
  };
}

/** Reads dropped folder or files from HTML5 DragEvent */
export async function readDroppedItems(dataTransfer: DataTransfer): Promise<{
  projectName: string;
  files: VirtualFile[];
}> {
  const items = Array.from(dataTransfer.items ?? []);
  const entries: WebkitEntry[] = [];

  for (const item of items) {
    const getter = (item as DataTransferItem & { webkitGetAsEntry?: () => WebkitEntry | null })
      .webkitGetAsEntry;
    if (typeof getter === 'function') {
      const entry = getter.call(item);
      if (entry) entries.push(entry);
    }
  }

  if (entries.length === 0) {
    return readFileListFromInput(dataTransfer.files);
  }

  const files: VirtualFile[] = [];
  const rootName =
    entries.length === 1 && entries[0].isDirectory ? entries[0].name : 'dropped-project';

  async function walkEntry(entry: WebkitEntry, prefix: string): Promise<void> {
    if (entry.isFile && entry.file) {
      if (isBinaryName(entry.name)) return;
      const fileObj = await new Promise<File | null>((res) =>
        entry.file!(
          (f) => res(f),
          () => res(null),
        ),
      );
      if (!fileObj) return;
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
      const vf = await fileObjToVirtual(fileObj, rel);
      if (vf) files.push(vf);
    } else if (entry.isDirectory && entry.createReader) {
      if (SKIP_DIRS.has(entry.name)) return;
      const reader = entry.createReader();
      const childEntries: WebkitEntry[] = [];

      while (true) {
        const batch = await new Promise<WebkitEntry[]>((res) =>
          reader.readEntries(
            (b) => res(b),
            () => res([]),
          ),
        );
        if (batch.length === 0) break;
        childEntries.push(...batch);
      }

      const nextPrefix =
        entries.length === 1 && prefix === '' && entry === entries[0]
          ? ''
          : prefix
            ? `${prefix}/${entry.name}`
            : entry.name;

      for (const child of childEntries) {
        await walkEntry(child, nextPrefix);
      }
    }
  }

  for (const e of entries) {
    await walkEntry(e, '');
  }

  return { projectName: rootName, files };
}
