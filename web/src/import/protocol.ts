// What the import worker does with a request: the dispatcher turns typed operations into calls on
// the WebAssembly module, and `attachImportWorker` wires it to a message port. Neither touches
// `self`, so tests run both with a mocked module and a fake port. The messages are the contract of
// ./contract.ts: a request is `{ id, op, args }`, and the answer is any number of `progress`
// messages, then one `result` or one `error`.
import {
  type DetectResult,
  type ExportFormat,
  type ExportResult,
  type ImportBatch,
  type ImportErrorCode,
  type ImportOps,
  type ImportRequest,
  type ImportResponse,
  ImportWorkerError,
  type OpName,
} from './contract';
import type { ImportWasm, ImportWasmLoader } from './wasm';

export interface ImportDispatcherDeps {
  loadWasm: ImportWasmLoader;
  /** The clock the export's file name takes its date from. */
  now?: () => Date;
}

/** Reports how far an operation is: `done` of `total` steps. */
export type Progress = (done: number, total: number) => void;

export type ImportDispatcher = <Op extends OpName>(
  op: Op,
  args: ImportOps[Op]['args'],
  progress?: Progress,
) => Promise<ImportOps[Op]['result']>;

/** Every code the WebAssembly module throws, and the two this side adds. */
const CODES: ReadonlySet<string> = new Set<ImportErrorCode>([
  'too-large',
  'limit-exceeded',
  'unsupported',
  'empty',
  'malformed',
  'password-required',
  'bad-password',
  'kdf-out-of-bounds',
  'account-restricted',
  'unsupported-encryption',
  'unavailable',
  'cancelled',
]);

/**
 * Maps whatever was thrown to a code. The module throws a code's name and nothing else; a trap
 * or a type error is `malformed`, and a module that will not start is `unavailable`.
 */
export function codeOf(error: unknown): ImportErrorCode {
  if (error instanceof ImportWorkerError) return error.code;
  if (error instanceof Error && CODES.has(error.message)) return error.message as ImportErrorCode;
  return 'malformed';
}

/** The kinds of export the worker writes; CSV is written by the page. */
const EXPORT_FILES: Record<Exclude<ExportFormat, 'csv'>, string> = {
  'kemlock-json': 'kemlock-export',
  'bitwarden-json': 'bitwarden-export',
};

function isWorkerExport(format: string): format is Exclude<ExportFormat, 'csv'> {
  return Object.prototype.hasOwnProperty.call(EXPORT_FILES, format);
}

export function createImportDispatcher(deps: ImportDispatcherDeps): ImportDispatcher {
  const now = deps.now ?? (() => new Date());
  let loading: Promise<ImportWasm> | undefined;

  async function wasm(): Promise<ImportWasm> {
    loading ??= deps.loadWasm().catch(() => {
      loading = undefined;
      throw new ImportWorkerError('unavailable');
    });
    return loading;
  }

  const handlers: {
    [Op in OpName]: (
      progress: Progress,
      ...args: ImportOps[Op]['args']
    ) => Promise<ImportOps[Op]['result']>;
  } = {
    async detect(_progress, bytes) {
      return JSON.parse((await wasm()).detect(bytes)) as DetectResult;
    },
    async parse(progress, bytes, format, password, keyFile) {
      const module = await wasm();
      // Reading is one synchronous call, so the page sees the start and the end.
      progress(0, 1);
      const batch = JSON.parse(module.parse(bytes, format, password, keyFile)) as ImportBatch;
      progress(1, 1);
      return batch;
    },
    async exportEncrypted(_progress, format, items, password) {
      if (!isWorkerExport(format)) throw new ImportWorkerError('unsupported');
      if (password === '') throw new ImportWorkerError('password-required');
      const module = await wasm();
      const bytes = module.exportEncrypted(format, JSON.stringify(items), password);
      const date = now().toISOString().slice(0, 10);
      return {
        bytes,
        filename: `${EXPORT_FILES[format]}-${date}.json`,
        mime: 'application/json',
      } satisfies ExportResult;
    },
  };

  const dispatch = (op: string, args: unknown[], progress: Progress = () => undefined) => {
    if (!Object.prototype.hasOwnProperty.call(handlers, op)) {
      return Promise.reject(new ImportWorkerError('unsupported'));
    }
    const handler = handlers[op as OpName] as (progress: Progress, ...a: unknown[]) => Promise<unknown>;
    try {
      return handler(progress, ...args);
    } catch (error) {
      return Promise.reject(error);
    }
  };
  return dispatch as ImportDispatcher;
}

/** What `attachImportWorker` needs of a worker's global scope. */
export interface ImportWorkerScope {
  addEventListener(type: 'message', listener: (event: { data: unknown }) => void): void;
  postMessage(message: ImportResponse, transfer?: Transferable[]): void;
}

function isRequest(value: unknown): value is ImportRequest {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  return typeof v['id'] === 'number' && typeof v['op'] === 'string' && Array.isArray(v['args']);
}

/** An export's bytes are handed over, not copied. */
function transferOf(result: unknown): Transferable[] {
  if (typeof result === 'object' && result !== null) {
    const bytes = (result as { bytes?: unknown }).bytes;
    if (bytes instanceof Uint8Array && bytes.buffer instanceof ArrayBuffer) return [bytes.buffer];
  }
  return [];
}

/**
 * Answers requests one at a time, in the order they came: reading a large file blocks the worker
 * anyway, and two files are never open at once.
 */
export function attachImportWorker(scope: ImportWorkerScope, dispatch: ImportDispatcher): void {
  let queue: Promise<void> = Promise.resolve();
  scope.addEventListener('message', (event) => {
    const request = event.data;
    if (!isRequest(request)) return;
    queue = queue.then(async () => {
      try {
        const result = await (dispatch as unknown as (
          op: string,
          args: unknown[],
          progress: Progress,
        ) => Promise<unknown>)(request.op, request.args, (done, total) =>
          scope.postMessage({ id: request.id, kind: 'progress', done, total }),
        );
        scope.postMessage({ id: request.id, kind: 'result', result }, transferOf(result));
      } catch (error) {
        scope.postMessage({ id: request.id, kind: 'error', code: codeOf(error) });
      }
    });
  });
}
