import { runRepoXray } from '../core/scanner';
import type { ScanOptions, ScanReport, VirtualFile } from '../core/types';
import type { WorkerScanRequest, WorkerScanResponse } from './scan.worker';

let sharedWorker: Worker | null = null;
let requestCounter = 1;

function getOrCreateWorker(): Worker | null {
  if (typeof Worker === 'undefined') return null;
  if (sharedWorker) return sharedWorker;
  try {
    sharedWorker = new Worker(new URL('./scan.worker.ts', import.meta.url), {
      type: 'module',
    });
    return sharedWorker;
  } catch {
    return null;
  }
}

/**
 * Executes RepoXray inside a dedicated off-main-thread Web Worker so heavy entropy
 * and regex scanning never blocks 60fps UI animations, with automatic fallback.
 */
export async function executeRepoXrayScan(
  files: VirtualFile[],
  options: ScanOptions = {},
): Promise<ScanReport> {
  const worker = getOrCreateWorker();
  if (!worker) {
    return runRepoXray(files, options);
  }

  const id = requestCounter++;

  return new Promise<ScanReport>((resolve, reject) => {
    const handleMessage = (event: MessageEvent<WorkerScanResponse>) => {
      const msg = event.data;
      if (!msg || msg.id !== id) return;

      if (msg.type === 'progress') {
        options.onProgress?.(msg.message);
      } else if (msg.type === 'result') {
        cleanup();
        resolve(msg.report);
      } else if (msg.type === 'error') {
        cleanup();
        reject(new Error(msg.message));
      }
    };

    const handleError = () => {
      cleanup();
      // Fallback transparently to main thread if worker fails to load under strict environments
      runRepoXray(files, options).then(resolve, reject);
    };

    const cleanup = () => {
      worker.removeEventListener('message', handleMessage);
      worker.removeEventListener('error', handleError);
    };

    worker.addEventListener('message', handleMessage);
    worker.addEventListener('error', handleError);

    const payload: WorkerScanRequest = {
      id,
      files,
      projectName: options.projectName ?? 'local-workspace',
      offline: options.offline,
    };
    worker.postMessage(payload);
  });
}
