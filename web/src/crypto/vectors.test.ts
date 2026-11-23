// @vitest-environment node
/// <reference types="vite/client" />
// The real WebAssembly module against test-vectors/*.json, read at test time. It runs once
// web/scripts/build-wasm.sh has built the module into ./pkg and is skipped before that.
//
// Through the worker's own API only values that are not secret can be compared: a bundle's
// fingerprint and signature, TOTP enrolment, the Argon2id bounds and the OPAQUE message sizes.
// The vectors that need keys (Argon2id output, password wrap, kem1 items, kx1, sig1, sealed
// boxes) are checked inside WebAssembly by crates/kemlock-wasm/src/tests.rs, which can see them.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { beforeAll, describe, expect, it } from 'vitest';

import { createDispatcher, type Dispatcher } from './protocol';
import type { WasmFactory } from './wasm';

const loaders = import.meta.glob('./pkg/kemlock_wasm.js');
const built = Object.keys(loaders).length > 0;

interface Vector {
  [field: string]: string | undefined;
  bundle: string;
  signature: string;
  fingerprint_text: string;
  salt: string;
}

function vectors(name: string): Vector[] {
  const path = fileURLToPath(new URL(`../../../test-vectors/${name}.json`, import.meta.url));
  const doc = JSON.parse(readFileSync(path, 'utf8')) as { cases: Vector[] };
  return doc.cases;
}

const b64url = (hex: string) => Buffer.from(hex, 'hex').toString('base64url');

describe.skipIf(!built)('the WebAssembly module', () => {
  let dispatch: Dispatcher;

  beforeAll(async () => {
    const module = (await (loaders['./pkg/kemlock_wasm.js'] as () => Promise<unknown>)()) as {
      initSync: (input: { module: Uint8Array }) => unknown;
      Vault: new () => import('./wasm').WasmVault;
    };
    const wasm = readFileSync(fileURLToPath(new URL('./pkg/kemlock_wasm_bg.wasm', import.meta.url)));
    module.initSync({ module: wasm });
    const factory: WasmFactory = () => new module.Vault();
    dispatch = createDispatcher({
      loadWasm: async () => factory,
      dpop: { proof: async () => '', reset: async () => undefined },
    });
  });

  it('gives the fingerprint of every bundle vector', async () => {
    for (const vector of vectors('bundle')) {
      expect(await dispatch('fingerprint', [b64url(vector.bundle)])).toBe(vector.fingerprint_text);
    }
  });

  it('verifies the bundle vectors and nothing altered', async () => {
    for (const vector of vectors('bundle')) {
      const bundle = b64url(vector.bundle);
      const signature = b64url(vector.signature);
      expect(await dispatch('verifyBundle', [bundle, signature])).toBe(true);

      const badSignature = Buffer.from(vector.signature, 'hex');
      badSignature[3] = (badSignature[3] ?? 0) ^ 1;
      expect(await dispatch('verifyBundle', [bundle, badSignature.toString('base64url')])).toBe(false);

      const badBundle = Buffer.from(vector.bundle, 'hex');
      badBundle[40] = (badBundle[40] ?? 0) ^ 1;
      expect(await dispatch('verifyBundle', [badBundle.toString('base64url'), signature])).toBe(false);
      expect(await dispatch('verifyBundle', ['not base64url!', signature])).toBe(false);
    }
  });

  it('refuses Argon2id settings outside the server bounds', async () => {
    const salt = b64url((vectors('argon2id')[0] as Vector).salt);
    for (const kdf of [
      { memoryKib: 64, iterations: 2, parallelism: 1, salt }, // the vector's own, far under the floor
      { memoryKib: 65536, iterations: 1, parallelism: 4, salt },
      { memoryKib: 65536, iterations: 3, parallelism: 17, salt },
      { memoryKib: 2 * 1024 * 1024, iterations: 3, parallelism: 4, salt },
    ]) {
      await expect(dispatch('masterKey', ['password', kdf])).rejects.toMatchObject({ code: 'invalid' });
    }
  });

  it('runs OPAQUE start messages of the sizes the protocol fixes', async () => {
    const salt = b64url('1b9f4c86e60b71d48cc763f1f674d426');
    const master = await dispatch('masterKey', ['correct horse battery staple', { memoryKib: 16384, iterations: 2, parallelism: 1, salt }]);
    const registration = await dispatch('opaqueRegisterStart', [master]);
    expect(Buffer.from(registration.request, 'base64url')).toHaveLength(32);
    const login = await dispatch('opaqueLoginStart', [master]);
    expect(Buffer.from(login.request, 'base64url')).toHaveLength(96);
    // A response that is not the server's is refused, and the state is spent.
    await expect(dispatch('opaqueLoginFinish', [login.state, master, 'AAAA'])).rejects.toMatchObject({ code: 'invalid' });
    await expect(dispatch('opaqueLoginFinish', [login.state, master, 'AAAA'])).rejects.toMatchObject({ code: 'invalid' });
    await dispatch('lock', []);
    await expect(dispatch('opaqueLoginStart', [master])).rejects.toMatchObject({ code: 'invalid' });
  });

  it('enrols TOTP with a 160-bit secret and a key URI', async () => {
    const fresh = await dispatch('totpUri', [undefined, { issuer: 'Kemlock Vault', account: 'alice@example.com' }]);
    expect(fresh.secret).toMatch(/^[A-Z2-7]{32}$/);
    expect(fresh.uri).toBe(
      `otpauth://totp/Kemlock%20Vault:alice%40example.com?secret=${fresh.secret}&issuer=Kemlock%20Vault&algorithm=SHA1&digits=6&period=30`,
    );
    const known = await dispatch('totpUri', ['jbsw y3dp ehpk 3pxp']);
    expect(known.secret).toBe('JBSWY3DPEHPK3PXP');
    await expect(dispatch('totpUri', ['MZXW6YQ='])).rejects.toMatchObject({ code: 'invalid' });
  });

  it('refuses item work while locked', async () => {
    await dispatch('lock', []);
    const address = { id: '00010203-0405-0607-0809-0a0b0c0d0e0f', owner: 'user:00010203-0405-0607-0809-0a0b0c0d0e0f', kind: 'login', revision: 1 };
    await expect(dispatch('sealItem', [{ ...address, json: '{}' }])).rejects.toMatchObject({ code: 'locked' });
    await expect(dispatch('openItem', [{ ...address, ciphertext: 'AAAA', itemKey: 'AAAA' }])).rejects.toMatchObject({ code: 'locked' });
  });
});

describe.skipIf(!built)('the sharing and space operations of the real module', () => {
  let dispatch: Dispatcher;
  const space = '00010203-0405-0607-0809-0a0b0c0d0e0f';

  beforeAll(async () => {
    const module = (await (loaders['./pkg/kemlock_wasm.js'] as () => Promise<unknown>)()) as {
      initSync: (input: { module: Uint8Array }) => unknown;
      Vault: new () => import('./wasm').WasmVault;
    };
    const wasm = readFileSync(fileURLToPath(new URL('./pkg/kemlock_wasm_bg.wasm', import.meta.url)));
    module.initSync({ module: wasm });
    const factory: WasmFactory = () => new module.Vault();
    dispatch = createDispatcher({
      loadWasm: async () => factory,
      dpop: { proof: async () => '', reset: async () => undefined },
    });
  });

  it('seals and signs nothing while locked', async () => {
    await dispatch('lock', []);
    const bundle = b64url((vectors('bundle')[0] as Vector).bundle);
    const kx1 = Buffer.from(bundle, 'base64url').subarray(37, 37 + 1600).toString('base64url');
    await expect(dispatch('sealRootKey', [kx1, 'emergency-access', 'AAAAAAAAAAAAAAAAAAAAAA'])).rejects.toMatchObject({
      code: 'locked',
    });
    await expect(dispatch('signStatement', ['AAAA', 'confirm'])).rejects.toMatchObject({ code: 'locked' });
    await expect(
      dispatch('newSpace', [{ spaceId: space, collectionId: space, spaceName: 'a', collectionName: 'b' }]),
    ).rejects.toMatchObject({ code: 'locked' });
  });

  it('verifies a confirmation as false when its parts are not a confirmation', async () => {
    const bundle = b64url((vectors('bundle')[0] as Vector).bundle);
    expect(
      await dispatch('verifyConfirmation', [
        {
          space,
          member: space,
          memberKeyVersion: 1,
          fingerprint: Buffer.alloc(64).toString('base64url'),
          confirmerBundle: bundle,
          statement: Buffer.alloc(134).toString('base64url'),
          signature: Buffer.alloc(3373).toString('base64url'),
        },
      ]),
    ).toBe(false);
    expect(
      await dispatch('verifyConfirmation', [
        { space: 'not a uuid', member: space, memberKeyVersion: 1, fingerprint: 'AA', confirmerBundle: bundle, statement: 'AA', signature: 'AA' },
      ]),
    ).toBe(false);
  });
});

describe('the vectors the web vault relies on', () => {
  it('are present and carry the fields the checks read', () => {
    for (const vector of vectors('bundle')) {
      expect(vector.fingerprint_text).toMatch(/^(\d{5} ){11}\d{5}$/);
    }
    expect(vectors('argon2id').length).toBeGreaterThan(0);
  });
});
