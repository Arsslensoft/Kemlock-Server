// @vitest-environment node
// The import worker's protocol, with the WebAssembly module mocked: what the dispatcher passes to
// the module, how it shapes the answers, how it fails, that progress and results come in the
// order the contract says, and the page's client talking to the real worker loop through an
// in-memory channel.
import { describe, expect, it, vi } from 'vitest';

import { createImportClient, type ImportWorkerPort } from './client';
import { type ExportItem, type ImportBatch, type ImportResponse, ImportWorkerError } from './contract';
import {
  attachImportWorker,
  codeOf,
  createImportDispatcher,
  type ImportDispatcher,
  type ImportWorkerScope,
} from './protocol';
import type { ImportWasm } from './wasm';

const EMPTY_BATCH: ImportBatch = {
  format: 'chrome-csv',
  folders: [],
  spaces: [],
  logins: [],
  codes: [],
  notes: [],
  cards: [],
  identities: [],
  ssh_keys: [],
  files: [],
  skipped: [],
};

function mockWasm(over: Partial<ImportWasm> = {}): ImportWasm {
  return {
    detect: vi.fn(() => JSON.stringify({ format: 'chrome-csv', encrypted: false })),
    parse: vi.fn(() => JSON.stringify(EMPTY_BATCH)),
    exportEncrypted: vi.fn(() => new Uint8Array([123, 125])),
    ...over,
  };
}

const NOW = () => new Date('2026-11-22T10:00:00Z');

function setup(wasm: ImportWasm = mockWasm()) {
  const loadWasm = vi.fn(async () => wasm);
  return { dispatch: createImportDispatcher({ loadWasm, now: NOW }), loadWasm, wasm };
}

const BYTES = new TextEncoder().encode('name,url');

describe('the dispatcher', () => {
  it('loads the module once, on first use', async () => {
    const { dispatch, loadWasm } = setup();
    expect(loadWasm).not.toHaveBeenCalled();
    await dispatch('detect', [BYTES]);
    await dispatch('detect', [BYTES]);
    expect(loadWasm).toHaveBeenCalledTimes(1);
  });

  it('answers a module that will not start with unavailable, and tries again next time', async () => {
    let attempts = 0;
    const wasm = mockWasm();
    const dispatch = createImportDispatcher({
      loadWasm: async () => {
        attempts += 1;
        if (attempts === 1) throw new Error('no wasm');
        return wasm;
      },
    });
    await expect(dispatch('detect', [BYTES])).rejects.toMatchObject({ code: 'unavailable' });
    expect(await dispatch('detect', [BYTES])).toEqual({ format: 'chrome-csv', encrypted: false });
  });

  it('parses the detect answer into an object', async () => {
    const { dispatch, wasm } = setup(
      mockWasm({ detect: vi.fn(() => '{"format":"bitwarden-json","encrypted":true}') }),
    );
    expect(await dispatch('detect', [BYTES])).toEqual({ format: 'bitwarden-json', encrypted: true });
    expect(wasm.detect).toHaveBeenCalledWith(BYTES);
  });

  it('passes parse its format, password and key file, and returns the batch', async () => {
    const { dispatch, wasm } = setup();
    const keyFile = new Uint8Array([1, 2, 3]);
    const batch = await dispatch('parse', [BYTES, 'kdbx', 'correct horse', keyFile]);
    expect(batch).toEqual(EMPTY_BATCH);
    expect(wasm.parse).toHaveBeenCalledWith(BYTES, 'kdbx', 'correct horse', keyFile);
    await dispatch('parse', [BYTES]);
    expect(wasm.parse).toHaveBeenLastCalledWith(BYTES, undefined, undefined, undefined);
  });

  it('reports the start and the end of a read', async () => {
    const { dispatch } = setup();
    const progress = vi.fn();
    await dispatch('parse', [BYTES], progress);
    expect(progress.mock.calls).toEqual([
      [0, 1],
      [1, 1],
    ]);
  });

  it('writes an export and names its file by kind and date', async () => {
    const { dispatch, wasm } = setup();
    const items: ExportItem[] = [{ id: 'a', kind: 'note', data: { name: 'n' } }];
    const result = await dispatch('exportEncrypted', ['bitwarden-json', items, 'a password']);
    expect(result).toEqual({
      bytes: new Uint8Array([123, 125]),
      filename: 'bitwarden-export-2026-11-22.json',
      mime: 'application/json',
    });
    expect(wasm.exportEncrypted).toHaveBeenCalledWith('bitwarden-json', JSON.stringify(items), 'a password');
    const kemlock = await dispatch('exportEncrypted', ['kemlock-json', items, 'a password']);
    expect(kemlock.filename).toBe('kemlock-export-2026-11-22.json');
  });

  it('refuses an export it can not write before it loads the module', async () => {
    const { dispatch, loadWasm } = setup();
    await expect(dispatch('exportEncrypted', ['csv' as never, [], 'pw'])).rejects.toMatchObject({
      code: 'unsupported',
    });
    await expect(dispatch('exportEncrypted', ['kemlock-json', [], ''])).rejects.toMatchObject({
      code: 'password-required',
    });
    expect(loadWasm).not.toHaveBeenCalled();
  });

  it('refuses an operation it does not know', async () => {
    const { dispatch } = setup();
    const loose = dispatch as unknown as (op: string, args: unknown[]) => Promise<unknown>;
    await expect(loose('constructor', [])).rejects.toMatchObject({ code: 'unsupported' });
    await expect(loose('nope', [])).rejects.toMatchObject({ code: 'unsupported' });
  });
});

describe('error codes', () => {
  it('pass through the names the module throws', () => {
    for (const code of [
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
    ]) {
      expect(codeOf(new Error(code))).toBe(code);
    }
    expect(codeOf(new ImportWorkerError('cancelled'))).toBe('cancelled');
  });

  it('turn anything else into malformed, never a message', () => {
    expect(codeOf(new Error('RuntimeError: unreachable at secret.csv line 3'))).toBe('malformed');
    expect(codeOf('a string')).toBe('malformed');
    expect(codeOf(undefined)).toBe('malformed');
    expect(codeOf(new TypeError('x is not a function'))).toBe('malformed');
  });
});

/** Both ends of a worker, in memory. Messages are structured-cloned, as postMessage does. */
function channel(dispatch: ImportDispatcher) {
  const toPage: Array<(event: { data: unknown }) => void> = [];
  let toWorker: ((event: { data: unknown }) => void) | undefined;
  const transfers: Array<Transferable[] | undefined> = [];
  const posted: ImportResponse[] = [];

  const scope: ImportWorkerScope = {
    addEventListener: (_type, listener) => {
      toWorker = listener;
    },
    postMessage: (message, transfer) => {
      posted.push(message);
      transfers.push(transfer);
      const data = structuredClone(message, transfer ? { transfer } : undefined);
      queueMicrotask(() => toPage.forEach((listener) => listener({ data })));
    },
  };
  attachImportWorker(scope, dispatch);

  const port: ImportWorkerPort = {
    postMessage(message, transfer) {
      const data = structuredClone(message, transfer ? { transfer } : undefined);
      queueMicrotask(() => toWorker?.({ data }));
    },
    addEventListener(type: string, listener: (event: never) => void) {
      if (type === 'message') toPage.push(listener as (event: { data: unknown }) => void);
    },
    terminate: vi.fn(),
  };
  return { port, posted, transfers };
}

describe('the worker loop with the page’s client', () => {
  it('answers detect and parse, with progress between a request and its result', async () => {
    const { dispatch } = setup();
    const { port, posted } = channel(dispatch);
    const client = createImportClient(() => port);
    expect(await client.detect(BYTES)).toEqual({ format: 'chrome-csv', encrypted: false });
    const onProgress = vi.fn();
    expect(await client.parse(BYTES, { onProgress })).toEqual(EMPTY_BATCH);
    expect(onProgress.mock.calls).toEqual([
      [0, 1],
      [1, 1],
    ]);
    expect(posted.map((m) => m.kind)).toEqual(['result', 'progress', 'progress', 'result']);
  });

  it('hands an export’s bytes over instead of copying them', async () => {
    const { dispatch } = setup();
    const { port, transfers } = channel(dispatch);
    const client = createImportClient(() => port);
    const result = await client.exportEncrypted('kemlock-json', [{ id: 'a', kind: 'note', data: {} }], 'pw');
    expect(result.filename).toBe('kemlock-export-2026-11-22.json');
    expect(result.bytes).toEqual(new Uint8Array([123, 125]));
    expect(transfers.at(-1)).toHaveLength(1);
  });

  it('rejects with the code the module threw and nothing else', async () => {
    const { dispatch } = setup(
      mockWasm({
        parse: vi.fn(() => {
          throw new Error('bad-password');
        }),
        detect: vi.fn(() => {
          throw new Error('RuntimeError: unreachable');
        }),
      }),
    );
    const { port } = channel(dispatch);
    const client = createImportClient(() => port);
    await expect(client.parse(BYTES, { password: 'x' })).rejects.toMatchObject({ code: 'bad-password' });
    await expect(client.detect(BYTES)).rejects.toMatchObject({ code: 'malformed' });
  });

  it('answers requests one at a time, in order', async () => {
    const order: string[] = [];
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const wasm = mockWasm({
      detect: vi.fn(() => {
        order.push('detect');
        return JSON.stringify({ format: 'chrome-csv', encrypted: false });
      }),
      parse: vi.fn(() => {
        order.push('parse');
        return JSON.stringify(EMPTY_BATCH);
      }),
    });
    const dispatch = createImportDispatcher({
      loadWasm: async () => {
        await gate;
        return wasm;
      },
    });
    const { port } = channel(dispatch);
    const client = createImportClient(() => port);
    const first = client.parse(BYTES);
    const second = client.detect(BYTES);
    release();
    await Promise.all([first, second]);
    expect(order).toEqual(['parse', 'detect']);
  });

  it('ignores messages that are not requests', async () => {
    const { dispatch } = setup();
    const { port, posted } = channel(dispatch);
    const client = createImportClient(() => port);
    await client.detect(BYTES);
    const count = posted.length;
    // Nothing is answered for these, and the loop still serves the next real request.
    for (const junk of [null, 'text', { id: 'x' }, { id: 1, op: 'detect' }, { id: 1, op: 5, args: [] }]) {
      port.postMessage(junk as never);
    }
    await Promise.resolve();
    expect(posted.length).toBe(count);
    expect(await client.detect(BYTES)).toEqual({ format: 'chrome-csv', encrypted: false });
  });
});
