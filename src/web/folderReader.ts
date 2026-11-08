import { isBinaryFileName, SKIP_DIRS } from '../core/fsFilters';
import type { VirtualFile } from '../core/types';

/** Hard caps to guarantee browser tab RAM never OOMs on massive monorepos */
const MAX_SCANNED_FILES = 4_500;
const MAX_SINGLE_FILE_BYTES = 300_000;
const MAX_TOTAL_TEXT_BYTES = 25 * 1024 * 1024;

interface ReaderBudget {
  loadedTextBytes: number;
  fileCount: number;
}

async function fileObjToVirtual(
  file: File,
  relPath: string,
  budget: ReaderBudget,
): Promise<VirtualFile | null> {
  if (budget.fileCount >= MAX_SCANNED_FILES) return null;

  const normalized = relPath.replace(/\\/g, '/').replace(/^\/+/, '');
  const segments = normalized.split('/');
  if (segments.some((s) => SKIP_DIRS.has(s))) return null;
  const baseName = segments[segments.length - 1] ?? normalized;
  if (isBinaryFileName(baseName)) return null;

  budget.fileCount += 1;

  if (
    file.size > MAX_SINGLE_FILE_BYTES ||
    budget.loadedTextBytes + file.size > MAX_TOTAL_TEXT_BYTES
  ) {
    return {
      path: normalized,
      content: '',
      sizeBytes: file.size,
    };
  }

  const content = await file.text();
  budget.loadedTextBytes += file.size;
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
  const budget: ReaderBudget = { loadedTextBytes: 0, fileCount: 0 };

  async function traverse(dirHandle: FileSystemDirectoryHandle, prefix: string): Promise<void> {
    if (budget.fileCount >= MAX_SCANNED_FILES) return;
    const iterable = dirHandle as unknown as AsyncIterable<[string, FileSystemHandle]>;
    for await (const [name, handle] of iterable) {
      if (budget.fileCount >= MAX_SCANNED_FILES) break;
      if (handle.kind === 'directory') {
        if (SKIP_DIRS.has(name)) continue;
        await traverse(
          handle as FileSystemDirectoryHandle,
          prefix ? `${prefix}/${name}` : name,
        );
      } else if (handle.kind === 'file') {
        if (isBinaryFileName(name)) continue;
        const f = await (handle as FileSystemFileHandle).getFile();
        const rel = prefix ? `${prefix}/${name}` : name;
        const vf = await fileObjToVirtual(f, rel, budget);
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
  const budget: ReaderBudget = { loadedTextBytes: 0, fileCount: 0 };
  let rootName = 'local-folder';

  for (let i = 0; i < fileList.length; i++) {
    if (budget.fileCount >= MAX_SCANNED_FILES) break;
    const f = fileList[i];
    const rawRel = (f as File & { webkitRelativePath?: string }).webkitRelativePath || f.name;
    const parts = rawRel.split('/');
    if (parts.length > 1 && rootName === 'local-folder') {
      rootName = parts[0];
    }
    const stripped = parts.length > 1 ? parts.slice(1).join('/') : rawRel;
    const vf = await fileObjToVirtual(f, stripped, budget);
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
  const budget: ReaderBudget = { loadedTextBytes: 0, fileCount: 0 };
  const rootName =
    entries.length === 1 && entries[0].isDirectory ? entries[0].name : 'dropped-project';

  async function walkEntry(entry: WebkitEntry, prefix: string): Promise<void> {
    if (budget.fileCount >= MAX_SCANNED_FILES) return;

    if (entry.isFile && entry.file) {
      if (isBinaryFileName(entry.name)) return;
      const fileObj = await new Promise<File | null>((res) =>
        entry.file!(
          (f) => res(f),
          () => res(null),
        ),
      );
      if (!fileObj) return;
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
      const vf = await fileObjToVirtual(fileObj, rel, budget);
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
        if (budget.fileCount >= MAX_SCANNED_FILES) break;
        await walkEntry(child, nextPrefix);
      }
    }
  }

  for (const e of entries) {
    if (budget.fileCount >= MAX_SCANNED_FILES) break;
    await walkEntry(e, '');
  }

  return { projectName: rootName, files };
}
