// @vitest-environment node
// The page's client, talking to the real dispatcher through an in-memory channel that stands in
// for a Worker: typed calls, lazy start, error classes, transferables and a dying worker.

import { describe, expect, it, vi } from 'vitest';

import { createCryptoClient, CryptoError, type WorkerPort } from './index';
import { attachWorker, createDispatcher } from './protocol';
import type { WorkerRequest, WorkerResponse } from './types';
import type { WasmVault } from './wasm';

type Listener = (event: { data: unknown }) => void;

/** Both ends of a worker, in memory. Messages are structured-cloned, as postMessage does. */
function channel(vault: Partial<WasmVault>) {
  const toPage: Listener[] = [];
  const errors: ((event: unknown) => void)[] = [];
  const transfers: (Transferable[] | undefined)[] = [];
  const requests: WorkerRequest[] = [];
  let toWorker: Listener | undefined;

  attachWorker(
    {
      addEventListener: (_type, listener) => {
        toWorker = listener;
      },
      postMessage: (message: WorkerResponse) => {
        const data = structuredClone(message);
        queueMicrotask(() => toPage.forEach((listener) => listener({ data })));
      },
    },
    createDispatcher({
      loadWasm: async () => () => vault as WasmVault,
      dpop: { proof: async () => 'proof', reset: async () => undefined },
    }),
  );

  const port: WorkerPort = {
    postMessage(message, transfer) {
      requests.push(message);
      transfers.push(transfer);
      const data = structuredClone(message, transfer ? { transfer } : undefined);
      queueMicrotask(() => toWorker?.({ data }));
    },
    addEventListener(type: string, listener: (event: never) => void) {
      if (type === 'message') toPage.push(listener as Listener);
      else errors.push(listener as (event: unknown) => void);
    },
    terminate: vi.fn(),
  };
  return { port, requests, transfers, crash: () => errors.forEach((listener) => listener({})) };
}

const KDF = { memoryKib: 65536, iterations: 3, parallelism: 4, salt: 'c2FsdHNhbHRzYWx0c2FsdA' };

describe('the crypto client', () => {
  it('starts the worker on first use, once', async () => {
    const { port } = channel({ lock: vi.fn() });
    const factory = vi.fn(() => port);
    const client = createCryptoClient(factory);
    expect(factory).not.toHaveBeenCalled();
    await client.lock();
    await client.lock();
    expect(factory).toHaveBeenCalledTimes(1);
  });

  it('sends typed messages and returns the parsed answers', async () => {
    const vault = {
      masterKey: vi.fn(() => 3),
      opaqueRegisterStart: vi.fn(() => JSON.stringify({ state: 4, request: 'cmVx' })),
    };
    const { port, requests } = channel(vault);
    const client = createCryptoClient(() => port);
    const master = await client.masterKey('correct horse', KDF);
    expect(master).toBe(3);
    expect(await client.opaqueRegisterStart(master)).toEqual({ state: 4, request: 'cmVx' });
    expect(requests.map((r) => r.op)).toEqual(['masterKey', 'opaqueRegisterStart']);
    expect(new Set(requests.map((r) => r.id)).size).toBe(2);
  });

  it('transfers a byte password instead of copying it', async () => {
    const vault = { masterKey: vi.fn(() => 3) };
    const { port, transfers } = channel(vault);
    const client = createCryptoClient(() => port);
    const bytes = new TextEncoder().encode('hunter2');
    await client.masterKey(bytes, KDF);
    expect(transfers[0]).toEqual([bytes.buffer]);
    expect(bytes.byteLength).toBe(0); // detached by the transfer
    expect(vault.masterKey).toHaveBeenCalledWith('hunter2', 65536, 3, 4, KDF.salt);

    await client.masterKey('plain text', KDF);
    expect(transfers[1]).toEqual([]);
  });

  it('copies a file before transferring it, so the page keeps its bytes', async () => {
    const vault = {
      sendSealFile: vi.fn((_key: string, plain: Uint8Array) => new Uint8Array([...plain, 9])),
      sendOpenFile: vi.fn((_key: string, file: Uint8Array) => file.slice(0, -1)),
    };
    const { port, transfers } = channel(vault);
    const client = createCryptoClient(() => port);
    const bytes = new Uint8Array([1, 2, 3]);
    const sealed = await client.sealSendFile('k', bytes);
    expect([...sealed]).toEqual([1, 2, 3, 9]);
    expect(bytes.byteLength).toBe(3); // the page's array is not detached
    expect(transfers[0]).toHaveLength(1);
    expect([...(await client.openSendFile('k', sealed))]).toEqual([1, 2, 3]);
    expect(sealed.byteLength).toBe(4);
  });

  it('rejects with a CryptoError that carries only a code', async () => {
    const { port } = channel({
      openItem: vi.fn(() => {
        throw new Error('RuntimeError: secret detail');
      }),
      sealItem: vi.fn(() => {
        throw new Error('locked');
      }),
    });
    const client = createCryptoClient(() => port);
    const address = { id: 'a', owner: 'user:b', kind: 'login', revision: 1 };
    const failure = await client
      .openItem({ ...address, ciphertext: 'x', itemKey: 'y' })
      .catch((e: unknown) => e);
    expect(failure).toBeInstanceOf(CryptoError);
    expect(failure).toMatchObject({ code: 'invalid', message: 'invalid' });
    await expect(client.sealItem({ ...address, json: '{}' })).rejects.toMatchObject({ code: 'locked' });
  });

  it('answers concurrent calls with the right results', async () => {
    const { port } = channel({
      fingerprint: vi.fn((bundle: string) => `fp-${bundle}`),
    });
    const client = createCryptoClient(() => port);
    const all = await Promise.all(['a', 'b', 'c'].map((b) => client.fingerprint(b)));
    expect(all).toEqual(['fp-a', 'fp-b', 'fp-c']);
  });

  it('fails every pending call as unavailable when the worker dies, then starts a new one', async () => {
    const dead = channel({});
    const live = channel({ fingerprint: vi.fn(() => 'ok') });
    // A worker that never answers.
    dead.port.postMessage = () => undefined;
    const ports = [dead.port, live.port];
    const client = createCryptoClient(() => ports.shift() as WorkerPort);

    const pending = client.fingerprint('a');
    dead.crash();
    await expect(pending).rejects.toMatchObject({ code: 'unavailable' });
    expect(dead.port.terminate).toHaveBeenCalled();
    expect(await client.fingerprint('a')).toBe('ok');
  });

  it('reports a worker that cannot be created as unavailable', async () => {
    const client = createCryptoClient(() => {
      throw new Error('no workers here');
    });
    await expect(client.lock()).rejects.toMatchObject({ code: 'unavailable' });
  });

  it('carries the sharing and space operations through the worker as base64url', async () => {
    const SPACE = '00010203-0405-0607-0809-0a0b0c0d0e0f';
    const vault = {
      sealRootKey: vi.fn(() => 'Ym94'),
      sealEmergencyKey: vi.fn(() => 'ZW1l'),
      signStatement: vi.fn(() => 'c2ln'),
      newSpace: vi.fn(() =>
        JSON.stringify({ name: 'bg', sealedSpaceKey: 'c2s', collection: { name: 'Yw', sealedKey: 'Y2s' } }),
      ),
      openName: vi.fn(() => 'Family'),
      openEmergencyKey: vi.fn(() => 5),
    };
    const { port, requests } = channel(vault);
    const client = createCryptoClient(() => port);

    expect(await client.sealRootKey('a3g', 'device-approval', 'YWFk')).toBe('Ym94');
    expect(await client.sealEmergencyKey('YnVu', 'c2ln', SPACE)).toBe('ZW1l');
    expect(await client.signStatement('c3Rt', 'confirm')).toBe('c2ln');
    const made = await client.newSpace({
      spaceId: SPACE,
      collectionId: SPACE,
      spaceName: 'Family',
      collectionName: 'Everyone',
    });
    expect(made.collection).toEqual({ name: 'Yw', sealedKey: 'Y2s' });
    expect(
      await client.openName({ spaceId: SPACE, keyVersion: 1, kind: 'space', id: SPACE, ciphertext: 'Y3Q' }),
    ).toBe('Family');
    expect(await client.openEmergencyKey('c2VhbGVk')).toBe(5);
    expect(requests.map((r) => r.op)).toEqual([
      'sealRootKey',
      'sealEmergencyKey',
      'signStatement',
      'newSpace',
      'openName',
      'openEmergencyKey',
    ]);
    expect(vault.sealRootKey).toHaveBeenCalledWith('a3g', 'device-approval', 'YWFk');
    expect(vault.sealEmergencyKey).toHaveBeenCalledWith('YnVu', 'c2ln', SPACE);
  });

  it('answers a sealing request for a locked account as locked', async () => {
    const { port } = channel({
      sealRootKey: vi.fn(() => {
        throw new Error('locked');
      }),
      openSpace: vi.fn(() => {
        throw new Error('RuntimeError: unreachable');
      }),
    });
    const client = createCryptoClient(() => port);
    await expect(client.sealRootKey('a3g', 'device-approval', 'YWFk')).rejects.toMatchObject({
      code: 'locked',
    });
    await expect(
      client.openSpace({ spaceId: 'x', keyVersion: 1, sealed: 'c2s' }),
    ).rejects.toMatchObject({ code: 'invalid' });
  });

  it('takes DPoP from the worker', async () => {
    const { port } = channel({});
    const client = createCryptoClient(() => port);
    expect(await client.dpopProof('GET', 'https://x.test/kem/v1/items')).toBe('proof');
  });
});
