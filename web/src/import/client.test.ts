import { describe, expect, it, vi } from 'vitest';
import { FAKE_EXPORT_PASSWORD, createFakeImportWorker } from '@/test/fake-import-worker';
import { type ImportWorkerPort, createImportClient, importClient } from './client';
import { ImportWorkerError, WASM_EXPORTS } from './contract';

const utf8 = (text: string) => new TextEncoder().encode(text);

const BITWARDEN = JSON.stringify({
  items: [
    { type: 1, name: 'GitHub', login: { username: 'sam', password: 'pw', uris: [{ uri: 'https://github.com' }] } },
    { type: 2, name: 'A secure note' },
  ],
});

function setup() {
  const worker = createFakeImportWorker();
  return { worker, client: createImportClient(() => worker) };
}

describe('the import client', () => {
  it('detects a format without decrypting', async () => {
    const { client } = setup();
    expect(await client.detect(utf8(BITWARDEN))).toEqual({ format: 'bitwarden-json', encrypted: false });
    expect(await client.detect(utf8('{"passwordProtected":true}'))).toEqual({
      format: 'bitwarden-json',
      encrypted: true,
    });
    expect(await client.detect(utf8('name,login_uri,login_username,login_password\n'))).toMatchObject({
      format: 'bitwarden-csv',
    });
  });

  it('parses a file into a batch and reports progress', async () => {
    const { client } = setup();
    const progress: Array<[number, number]> = [];
    const batch = await client.parse(utf8(BITWARDEN), {
      onProgress: (done, total) => progress.push([done, total]),
    });
    expect(batch.format).toBe('bitwarden-json');
    expect(batch.logins).toHaveLength(1);
    expect(batch.logins[0]).toMatchObject({ name: 'GitHub', username: 'sam', password: 'pw' });
    expect(batch.skipped).toHaveLength(1);
    expect(progress).toEqual([[0, 1]]);
  });

  it('copies the bytes it transfers, so the caller can parse a file it just detected', async () => {
    const { client, worker } = setup();
    const bytes = utf8(BITWARDEN);
    await client.detect(bytes);
    await client.parse(bytes);
    expect(bytes.length).toBeGreaterThan(0);
    expect(worker.posted.map((m) => m.op)).toEqual(['detect', 'parse']);
  });

  it('answers a worker error with its code', async () => {
    const { client } = setup();
    await expect(client.detect(utf8('plain text'))).rejects.toMatchObject({ code: 'unsupported' });
    const protectedFile = utf8('{"passwordProtected":true}');
    await expect(client.parse(protectedFile)).rejects.toMatchObject({ code: 'password-required' });
    await expect(client.parse(protectedFile, { password: 'wrong' })).rejects.toMatchObject({
      code: 'bad-password',
    });
    await expect(client.parse(utf8('{"items":[]}'))).rejects.toBeInstanceOf(ImportWorkerError);
  });

  it('writes an encrypted export', async () => {
    const { client } = setup();
    const result = await client.exportEncrypted(
      'bitwarden-json',
      [{ id: 'a', kind: 'login', data: { name: 'GitHub' } }],
      FAKE_EXPORT_PASSWORD,
    );
    expect(result.filename).toBe('bitwarden-export.json');
    expect(JSON.parse(new TextDecoder().decode(result.bytes))).toMatchObject({
      fakeEncrypted: true,
      format: 'bitwarden-json',
      items: [{ id: 'a' }],
    });
    await expect(client.exportEncrypted('kemlock-json', [], '')).rejects.toMatchObject({
      code: 'password-required',
    });
  });

  it('answers unavailable when the worker cannot start, or dies', async () => {
    const broken = createImportClient(() => {
      throw new Error('no worker');
    });
    await expect(broken.detect(utf8('x'))).rejects.toMatchObject({ code: 'unavailable' });

    const errorListeners: Array<(event: unknown) => void> = [];
    const worker: ImportWorkerPort = {
      postMessage: vi.fn(),
      addEventListener(type: string, listener: (event: never) => void) {
        if (type === 'error') errorListeners.push(listener as (event: unknown) => void);
      },
      terminate: vi.fn(),
    };
    const client = createImportClient(() => worker);
    const pending = client.detect(utf8('x'));
    errorListeners.forEach((listener) => listener({}));
    await expect(pending).rejects.toMatchObject({ code: 'unavailable' });
  });

  it('is unavailable until a worker factory is installed', async () => {
    await expect(importClient.detect(utf8('x'))).rejects.toMatchObject({ code: 'unavailable' });
  });
});

describe('the contract', () => {
  it('lists what the wasm wrapper must export', () => {
    expect(WASM_EXPORTS).toHaveLength(3);
    expect(WASM_EXPORTS.join('\n')).toContain('detect(');
    expect(WASM_EXPORTS.join('\n')).toContain('parse(');
    expect(WASM_EXPORTS.join('\n')).toContain('exportEncrypted(');
  });
});
