// The page's side of the import worker: typed calls over `postMessage`, the same way
// src/crypto/index.ts talks to the crypto worker. A file's bytes are copied and the copy is
// transferred, so the caller keeps its own (it parses the file it just detected).
import {
  type DetectResult,
  type ExportFormat,
  type ExportItem,
  type ExportResult,
  type ImportBatch,
  type ImportFormat,
  type ImportOps,
  type ImportRequest,
  type ImportResponse,
  ImportWorkerError,
  type OpName,
} from './contract';

/** What the client needs of a `Worker`; the tests give it a fake. */
export interface ImportWorkerPort {
  postMessage(message: ImportRequest, transfer?: Transferable[]): void;
  addEventListener(type: 'message', listener: (event: { data: unknown }) => void): void;
  addEventListener(type: 'error' | 'messageerror', listener: (event: unknown) => void): void;
  terminate?(): void;
}

export interface ParseOptions {
  format?: ImportFormat;
  password?: string;
  keyFile?: Uint8Array;
  onProgress?: (done: number, total: number) => void;
}

export interface ImportClient {
  detect(bytes: Uint8Array): Promise<DetectResult>;
  parse(bytes: Uint8Array, options?: ParseOptions): Promise<ImportBatch>;
  exportEncrypted(
    format: Exclude<ExportFormat, 'csv'>,
    items: ExportItem[],
    password: string,
  ): Promise<ExportResult>;
  /** Stops the worker; the next call starts a new one. */
  dispose(): void;
}

interface Pending {
  resolve(value: unknown): void;
  reject(error: unknown): void;
  onProgress?: ((done: number, total: number) => void) | undefined;
}

/** A client over any worker factory. */
export function createImportClient(factory: () => ImportWorkerPort): ImportClient {
  let port: ImportWorkerPort | undefined;
  let nextId = 1;
  const pending = new Map<number, Pending>();

  function failAll(code: 'unavailable'): void {
    const error = new ImportWorkerError(code);
    for (const entry of pending.values()) entry.reject(error);
    pending.clear();
    port?.terminate?.();
    port = undefined;
  }

  function start(): ImportWorkerPort {
    if (port) return port;
    const created = factory();
    created.addEventListener('message', (event) => {
      const response = event.data as ImportResponse;
      const entry = pending.get(response.id);
      if (!entry) return;
      if (response.kind === 'progress') {
        entry.onProgress?.(response.done, response.total);
        return;
      }
      pending.delete(response.id);
      if (response.kind === 'result') entry.resolve(response.result);
      else entry.reject(new ImportWorkerError(response.code));
    });
    created.addEventListener('error', () => failAll('unavailable'));
    created.addEventListener('messageerror', () => failAll('unavailable'));
    port = created;
    return created;
  }

  function call<Op extends OpName>(
    op: Op,
    args: ImportOps[Op]['args'],
    transfer: Transferable[] = [],
    onProgress?: (done: number, total: number) => void,
  ): Promise<ImportOps[Op]['result']> {
    return new Promise((resolve, reject) => {
      let worker: ImportWorkerPort;
      try {
        worker = start();
      } catch {
        reject(new ImportWorkerError('unavailable'));
        return;
      }
      const id = nextId++;
      pending.set(id, { resolve: resolve as (value: unknown) => void, reject, onProgress });
      try {
        worker.postMessage({ id, op, args } as ImportRequest, transfer);
      } catch {
        pending.delete(id);
        reject(new ImportWorkerError('unavailable'));
      }
    });
  }

  return {
    detect(bytes) {
      const copy = bytes.slice();
      return call('detect', [copy], [copy.buffer]);
    },
    parse(bytes, options = {}) {
      const copy = bytes.slice();
      const keyFile = options.keyFile?.slice();
      const transfer: Transferable[] = [copy.buffer];
      if (keyFile) transfer.push(keyFile.buffer);
      return call('parse', [copy, options.format, options.password, keyFile], transfer, options.onProgress);
    },
    exportEncrypted: (format, items, password) => call('exportEncrypted', [format, items, password]),
    dispose() {
      failAll('unavailable');
    },
  };
}

let workerFactory: (() => ImportWorkerPort) | undefined;

/**
 * Where the real worker is plugged in: `installImportWorker()` (src/import/install.ts, called from
 * src/main.tsx) sets a factory that starts src/import/worker.ts. Until a factory is set the client
 * answers `unavailable` and the screen says so.
 */
export function setImportWorkerFactory(factory: (() => ImportWorkerPort) | undefined): void {
  workerFactory = factory;
}

export const importClient: ImportClient = createImportClient(() => {
  if (!workerFactory) throw new Error('the import worker is not installed');
  return workerFactory();
});
