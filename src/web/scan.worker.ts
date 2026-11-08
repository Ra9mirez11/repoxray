import { runRepoXray } from '../core/scanner';
import type { ScanReport, VirtualFile } from '../core/types';

export interface WorkerScanRequest {
  id: number;
  files: VirtualFile[];
  projectName: string;
  offline?: boolean;
}

export type WorkerScanResponse =
  | { id: number; type: 'progress'; message: string }
  | { id: number; type: 'result'; report: ScanReport }
  | { id: number; type: 'error'; message: string };

interface DedicatedWorkerGlobal {
  onmessage: ((event: MessageEvent<WorkerScanRequest>) => void) | null;
  postMessage: (message: WorkerScanResponse) => void;
}

const workerSelf = globalThis as unknown as DedicatedWorkerGlobal;

workerSelf.onmessage = async (event: MessageEvent<WorkerScanRequest>) => {
  const { id, files, projectName, offline } = event.data;
  try {
    const report = await runRepoXray(files, {
      projectName,
      offline,
      onProgress: (message) => {
        workerSelf.postMessage({ id, type: 'progress', message });
      },
    });
    workerSelf.postMessage({ id, type: 'result', report });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    workerSelf.postMessage({ id, type: 'error', message });
  }
};
