// @vitest-environment node
/// <reference types="vite/client" />
// The real import WebAssembly module against kemlock-import's fixtures, read at test time. It runs
// once web/scripts/build-wasm.sh has built the module into ./pkg and is skipped before that.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { beforeAll, describe, expect, it } from 'vitest';

import type { ImportBatch } from './contract';
import { createImportDispatcher, type ImportDispatcher } from './protocol';
import type { ImportWasm } from './wasm';

const loaders = import.meta.glob('./pkg/kemlock_import_wasm.js');
const built = Object.keys(loaders).length > 0;

function fixture(path: string): Uint8Array {
  return new Uint8Array(
    readFileSync(fileURLToPath(new URL(`../../../crates/kemlock-import/tests/fixtures/${path}`, import.meta.url))),
  );
}

describe.skipIf(!built)('the import WebAssembly module', () => {
  let dispatch: ImportDispatcher;

  beforeAll(async () => {
    const module = (await (loaders['./pkg/kemlock_import_wasm.js'] as () => Promise<unknown>)()) as {
      initSync: (input: { module: Uint8Array }) => unknown;
    } & ImportWasm;
    const wasm = readFileSync(fileURLToPath(new URL('./pkg/kemlock_import_wasm_bg.wasm', import.meta.url)));
    module.initSync({ module: wasm });
    dispatch = createImportDispatcher({
      loadWasm: async () => ({
        detect: (bytes) => module.detect(bytes),
        parse: (bytes, format, password, keyFile) => module.parse(bytes, format, password, keyFile),
        exportEncrypted: (kind, itemsJson, password) => module.exportEncrypted(kind, itemsJson, password),
      }),
    });
  });

  it('detects and reads a Chrome export', async () => {
    const bytes = fixture('chrome/passwords.csv');
    expect(await dispatch('detect', [bytes])).toEqual({ format: 'chrome-csv', encrypted: false });
    const batch = await dispatch('parse', [bytes]);
    expect(batch.format).toBe('chrome-csv');
    expect(batch.logins[0]?.name).toBe('Example Mail');
  });

  it('asks for a password, names a wrong one and opens with the right one', async () => {
    const bytes = fixture('bitwarden/protected-pbkdf2.json');
    expect(await dispatch('detect', [bytes])).toEqual({ format: 'bitwarden-json', encrypted: true });
    await expect(dispatch('parse', [bytes])).rejects.toMatchObject({ message: 'password-required' });
    await expect(dispatch('parse', [bytes, undefined, 'wrong'])).rejects.toMatchObject({
      message: 'bad-password',
    });
    const batch = await dispatch('parse', [bytes, undefined, 'correct horse']);
    expect(batch.logins.length).toBeGreaterThan(0);
  });

  it('writes an encrypted export that reads back with its password', async () => {
    const items = [
      { id: '11111111-1111-4111-8111-111111111111', kind: 'login', data: { name: 'Mail', username: 'ada', password: 'pw' } },
      { id: '22222222-2222-4222-8222-222222222222', kind: 'note', data: { name: 'Wifi', text: 'on the fridge' } },
    ];
    for (const format of ['bitwarden-json', 'kemlock-json'] as const) {
      const made = await dispatch('exportEncrypted', [format, items, 'correct horse']);
      expect(made.mime).toBe('application/json');
      expect(made.filename).toMatch(new RegExp(`^${format.split('-')[0]}-export-\\d{4}-\\d{2}-\\d{2}\\.json$`));
      const text = new TextDecoder().decode(made.bytes);
      expect(text.startsWith('{\n  "encrypted": true,\n  "passwordProtected": true,\n')).toBe(true);
      expect(text).toContain('"kdfType": 1');
      expect(text).not.toContain('"pw"');
      const batch: ImportBatch = await dispatch('parse', [made.bytes, undefined, 'correct horse']);
      expect(batch.logins[0]?.password).toBe('pw');
      expect(batch.notes[0]?.text).toBe('on the fridge');
      await expect(dispatch('parse', [made.bytes, undefined, 'wrong'])).rejects.toMatchObject({
        message: 'bad-password',
      });
    }
  });
});
