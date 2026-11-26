// @vitest-environment node
// The worker's protocol, with the WebAssembly module mocked: what the dispatcher passes to the
// vault, how it shapes the answers, how it fails, and that requests are served one at a time.

import { describe, expect, it, vi } from 'vitest';

import type { Dpop } from './dpop';
import { attachWorker, codeOf, createDispatcher, type WorkerScope } from './protocol';
import { CryptoError, type KdfSettings, type WorkerRequest, type WorkerResponse } from './types';
import type { WasmVault } from './wasm';

const KDF: KdfSettings = { memoryKib: 65536, iterations: 3, parallelism: 4, salt: 'c2FsdHNhbHRzYWx0c2FsdA' };
const UUID = '00010203-0405-0607-0809-0a0b0c0d0e0f';

function mockVault(overrides: Partial<WasmVault> = {}): WasmVault {
  return {
    masterKey: vi.fn(() => 7),
    release: vi.fn(),
    opaqueRegisterStart: vi.fn(() => JSON.stringify({ state: 8, request: 'cmVxdWVzdA' })),
    opaqueRegisterFinish: vi.fn(() => JSON.stringify({ upload: 'dXA', exportKey: 9 })),
    opaqueLoginStart: vi.fn(() => JSON.stringify({ state: 10, request: 'bG9naW4' })),
    opaqueLoginFinish: vi.fn(() => JSON.stringify({ finalization: 'Zmlu', exportKey: 11 })),
    newAccount: vi.fn(() =>
      JSON.stringify({
        publicBundle: 'YnVuZGxl',
        bundleSignature: 'c2ln',
        sealedPrivateKeys: 'c2VhbGVk',
        wrappedRootKey: 'd3JhcA',
        keyVersion: 1,
        fingerprint: '12345 67890',
      }),
    ),
    rewrapRoot: vi.fn(() => 'bmV3d3JhcA'),
    unlock: vi.fn(),
    isUnlocked: vi.fn(() => true),
    sealItem: vi.fn(() => JSON.stringify({ ciphertext: 'Y3Q', itemKey: 'aw', keyVersion: 1 })),
    openItem: vi.fn(() => '{"name":"x"}'),
    ownFingerprint: vi.fn(() => '11111 22222'),
    fingerprint: vi.fn(() => '33333 44444'),
    verifyBundle: vi.fn(() => true),
    totpEnrol: vi.fn(() => JSON.stringify({ secret: 'JBSWY3DPEHPK3PXP', uri: 'otpauth://totp/x' })),
    sendNewKey: vi.fn(() => 'a'.repeat(43)),
    sendSeal: vi.fn(() => JSON.stringify({ payload: 'cGF5bG9hZA', meta: 'bWV0YQ' })),
    sendOpenPayload: vi.fn(() => '{"name":"n","text":"t"}'),
    sendOpenMeta: vi.fn(() => '{"name":"n","notes":""}'),
    sendWrapKey: vi.fn(() => 'c2VhbGVk'),
    sendOpenKey: vi.fn(() => 'a'.repeat(43)),
    sendProof: vi.fn(() => 'p'.repeat(43)),
    sendSealFile: vi.fn((_key: string, plain: Uint8Array) => new Uint8Array([...plain, 1])),
    sendOpenFile: vi.fn((_key: string, file: Uint8Array) => file.slice(0, -1)),
    sealRootKey: vi.fn(() => 'cm9vdC1ib3g'),
    sealRootKeyForRecovery: vi.fn(() => 'cmVjb3Zlcnk'),
    confirmationStatement: vi.fn(() => 'c3RhdGVtZW50'),
    signStatement: vi.fn(() => 'c2ln'),
    verifyConfirmation: vi.fn(() => true),
    openEmergencyKey: vi.fn(() => 21),
    openEmergencyItem: vi.fn(() => '{"name":"bank"}'),
    newSpace: vi.fn(() =>
      JSON.stringify({
        name: 'bmFtZQ',
        sealedSpaceKey: 'c3BhY2U',
        collection: { name: 'Y29sbA', sealedKey: 'Y29sbC1rZXk' },
      }),
    ),
    openSpace: vi.fn(),
    openCollection: vi.fn(),
    openName: vi.fn(() => 'Family'),
    sealName: vi.fn(() => 'c2VhbGVk'),
    newCollection: vi.fn(() => JSON.stringify({ name: 'bmFtZQ', sealedKey: 'a2V5' })),
    sealSpaceKeyTo: vi.fn(() => 'c3BhY2Uta2V5'),
    sealCollectionKeyTo: vi.fn(() => 'Y29sbC1rZXk'),
    newDeviceKey: vi.fn(() => JSON.stringify({ handle: 31, publicKey: 'cHVi' })),
    openApprovedKey: vi.fn(() => 32),
    newSsoAccount: vi.fn(() =>
      JSON.stringify({
        publicBundle: 'YnVuZGxl',
        bundleSignature: 'c2ln',
        sealedPrivateKeys: 'c2VhbGVk',
        wrappedRootKey: '',
        keyVersion: 1,
        fingerprint: '12345',
      }),
    ),
    exportRoot: vi.fn(() => 'cm9vdA'),
    importRoot: vi.fn(() => 34),
    prfWrapRoot: vi.fn(() => JSON.stringify({ wrappedKey: 'd3JhcA', keyVersion: 3 })),
    prfOpenRoot: vi.fn(() => 33),
    kitMake: vi.fn(() =>
      JSON.stringify({ kitId: 'ABCDEFGH', pieces: ['p1', 'p2', 'p3'], wrappedKey: 'd3JhcA', keyVersion: 3 }),
    ),
    kitReadPiece: vi.fn(() => JSON.stringify({ problem: 'checksum' })),
    kitCheckPieces: vi.fn(() => JSON.stringify({ problem: 'duplicate' })),
    kitOpenRoot: vi.fn(() => 35),
    unlockWithRoot: vi.fn(),
    sealSpaceItem: vi.fn(() => JSON.stringify({ ciphertext: 'c2k', itemKey: 'a2s', keyVersion: 2 })),
    openSpaceItem: vi.fn(() => '{"name":"vpn"}'),
    manifestSign: vi.fn(() => 'c2lnbmF0dXJl'),
    manifestVerifyOwn: vi.fn(() => true),
    manifestVerify: vi.fn(() => true),
    lock: vi.fn(),
    free: vi.fn(),
    ...overrides,
  };
}

function dpopStub(): Dpop {
  return { proof: vi.fn(async () => 'proof'), reset: vi.fn(async () => undefined) };
}

function setup(vaults: WasmVault[] = [mockVault()]) {
  const queue = [...vaults];
  const factory = vi.fn(() => {
    const next = queue.shift();
    if (!next) throw new Error('no more vaults');
    return next;
  });
  const loadWasm = vi.fn(async () => factory);
  const dpop = dpopStub();
  return { dispatch: createDispatcher({ loadWasm, dpop }), loadWasm, factory, dpop };
}

describe('the dispatcher', () => {
  it('loads the module once, on first use', async () => {
    const { dispatch, loadWasm, factory } = setup();
    expect(loadWasm).not.toHaveBeenCalled();
    await dispatch('opaqueLoginStart', [7 as never]);
    await dispatch('opaqueLoginStart', [7 as never]);
    expect(loadWasm).toHaveBeenCalledTimes(1);
    expect(factory).toHaveBeenCalledTimes(1);
  });

  it('answers a module that will not start with unavailable', async () => {
    const dispatch = createDispatcher({
      loadWasm: async () => {
        throw new Error('no wasm');
      },
      dpop: dpopStub(),
    });
    await expect(dispatch('opaqueLoginStart', [1 as never])).rejects.toMatchObject({
      code: 'unavailable',
    });
  });

  it('turns a password into an NFC string and returns a handle', async () => {
    const vault = mockVault();
    const { dispatch } = setup([vault]);
    const handle = await dispatch('masterKey', ['café', KDF]);
    expect(handle).toBe(7);
    expect(vault.masterKey).toHaveBeenCalledWith('café', 65536, 3, 4, KDF.salt);
  });

  it('wipes a byte password after reading it', async () => {
    const vault = mockVault();
    const { dispatch } = setup([vault]);
    const bytes = new TextEncoder().encode('hunter2');
    await dispatch('masterKey', [bytes, KDF]);
    expect(vault.masterKey).toHaveBeenCalledWith('hunter2', 65536, 3, 4, KDF.salt);
    expect([...bytes]).toEqual(new Array(7).fill(0));
  });

  it('parses the vault answers into objects', async () => {
    const { dispatch } = setup();
    expect(await dispatch('opaqueRegisterStart', [7 as never])).toEqual({ state: 8, request: 'cmVxdWVzdA' });
    expect(await dispatch('opaqueRegisterFinish', [8 as never, 7 as never, 'cmVz'])).toEqual({
      upload: 'dXA',
      exportKey: 9,
    });
    expect(await dispatch('opaqueLoginStart', [7 as never])).toEqual({ state: 10, request: 'bG9naW4' });
    expect(await dispatch('opaqueLoginFinish', [10 as never, 7 as never, 'cmVz'])).toEqual({
      finalization: 'Zmlu',
      exportKey: 11,
    });
    const account = await dispatch('newAccount', [UUID, 7 as never, 9 as never]);
    expect(account.keyVersion).toBe(1);
    expect(account.fingerprint).toBe('12345 67890');
  });

  it('wraps the open root key under the new master and export keys, handing back the wrap', async () => {
    const vault = mockVault();
    const { dispatch } = setup([vault]);
    expect(await dispatch('rewrapRoot', [7 as never, 9 as never])).toBe('bmV3d3JhcA');
    expect(vault.rewrapRoot).toHaveBeenCalledWith(7, 9);
  });

  it('unlocks with key version 1 unless told otherwise', async () => {
    const vault = mockVault();
    const { dispatch } = setup([vault]);
    await dispatch('unlock', [UUID, 'd3JhcA', 7 as never, 9 as never]);
    expect(vault.unlock).toHaveBeenLastCalledWith(UUID, 'd3JhcA', 7, 9, 1, undefined);
    await dispatch('unlock', [UUID, 'd3JhcA', 7 as never, 9 as never, { keyVersion: 2, sealedPrivateKeys: 'c2s' }]);
    expect(vault.unlock).toHaveBeenLastCalledWith(UUID, 'd3JhcA', 7, 9, 2, 'c2s');
  });

  it('seals and opens items with a BigInt revision', async () => {
    const vault = mockVault();
    const { dispatch } = setup([vault]);
    const sealed = await dispatch('sealItem', [
      { id: UUID, owner: `user:${UUID}`, kind: 'login', revision: 4, json: '{"a":1}' },
    ]);
    expect(sealed).toEqual({ ciphertext: 'Y3Q', itemKey: 'aw', keyVersion: 1 });
    expect(vault.sealItem).toHaveBeenCalledWith(UUID, `user:${UUID}`, 'login', 4n, '{"a":1}');

    const json = await dispatch('openItem', [
      { id: UUID, owner: `user:${UUID}`, kind: 'login', revision: 4, ciphertext: 'Y3Q', itemKey: 'aw' },
    ]);
    expect(json).toBe('{"name":"x"}');
    expect(vault.openItem).toHaveBeenCalledWith(UUID, `user:${UUID}`, 'login', 4n, 'Y3Q', 'aw', undefined);
  });

  it('refuses a revision that is not a safe non-negative integer', async () => {
    const { dispatch } = setup();
    for (const revision of [-1, 1.5, Number.NaN, 2 ** 53]) {
      await expect(
        dispatch('sealItem', [{ id: UUID, owner: `user:${UUID}`, kind: 'login', revision, json: '{}' }]),
      ).rejects.toMatchObject({ code: 'invalid' });
    }
  });

  it('passes a Send through to the vault, binding its id and kind', async () => {
    const vault = mockVault();
    const { dispatch } = setup([vault]);
    const key = 'a'.repeat(43);
    expect(await dispatch('sendNewKey', [])).toBe(key);

    const sealed = await dispatch('sealSend', [
      { id: UUID, kind: 'text', linkKey: key, payloadJson: '{"p":1}', metaJson: '{"m":1}' },
    ]);
    expect(sealed).toEqual({ payload: 'cGF5bG9hZA', meta: 'bWV0YQ' });
    expect(vault.sendSeal).toHaveBeenCalledWith(UUID, 'text', key, '{"p":1}', '{"m":1}');

    const address = { id: UUID, kind: 'text', linkKey: key, sealed: 'cGF5bG9hZA' };
    expect(await dispatch('openSendPayload', [address])).toBe('{"name":"n","text":"t"}');
    expect(vault.sendOpenPayload).toHaveBeenCalledWith(UUID, 'text', key, 'cGF5bG9hZA');
    // The meta takes the sealed key, never the link key.
    const metaInput = { id: UUID, kind: 'text', sealedKey: 'c2VhbGVk', sealed: 'bWV0YQ' };
    expect(await dispatch('openSendMeta', [metaInput])).toBe('{"name":"n","notes":""}');
    expect(vault.sendOpenMeta).toHaveBeenCalledWith(UUID, 'text', 'c2VhbGVk', 'bWV0YQ');

    expect(await dispatch('wrapSendKey', [UUID, key])).toBe('c2VhbGVk');
    expect(vault.sendWrapKey).toHaveBeenCalledWith(UUID, key);
    expect(await dispatch('unwrapSendKey', [UUID, 'c2VhbGVk'])).toBe(key);
    expect(vault.sendOpenKey).toHaveBeenCalledWith(UUID, 'c2VhbGVk');
    expect(await dispatch('sendProof', [UUID, key, 'hunter2'])).toBe('p'.repeat(43));
    expect(vault.sendProof).toHaveBeenCalledWith(UUID, key, 'hunter2');

    const file = await dispatch('sealSendFile', [key, new Uint8Array([5, 6])]);
    expect([...file]).toEqual([5, 6, 1]);
    expect([...(await dispatch('openSendFile', [key, file]))]).toEqual([5, 6]);
  });

  it('refuses a Send operation as invalid when the vault throws', async () => {
    const vault = mockVault({
      sendOpenPayload: vi.fn(() => {
        throw new Error('invalid');
      }),
    });
    const { dispatch } = setup([vault]);
    await expect(
      dispatch('openSendPayload', [{ id: UUID, kind: 'file', linkKey: 'k', sealed: 'x' }]),
    ).rejects.toThrow('invalid');
  });

  it('seals the root key and signs a confirmation through the vault', async () => {
    const vault = mockVault();
    const { dispatch } = setup([vault]);
    expect(await dispatch('sealRootKey', ['a2V5', 'device-approval', 'YWFk'])).toBe('cm9vdC1ib3g');
    expect(vault.sealRootKey).toHaveBeenCalledWith('a2V5', 'device-approval', 'YWFk');

    const facts = { space: UUID, member: UUID, memberKeyVersion: 2, fingerprint: 'ZnA' };
    expect(await dispatch('confirmationStatement', [facts])).toBe('c3RhdGVtZW50');
    expect(vault.confirmationStatement).toHaveBeenCalledWith(UUID, UUID, 2, 'ZnA');
    expect(await dispatch('signStatement', ['c3RhdGVtZW50', 'confirm'])).toBe('c2ln');
    expect(vault.signStatement).toHaveBeenCalledWith('c3RhdGVtZW50', 'confirm');
    expect(
      await dispatch('verifyConfirmation', [
        { ...facts, confirmerBundle: 'YnVuZGxl', statement: 'c3RhdGVtZW50', signature: 'c2ln' },
      ]),
    ).toBe(true);
    expect(vault.verifyConfirmation).toHaveBeenCalledWith(
      'YnVuZGxl',
      UUID,
      UUID,
      2,
      'ZnA',
      'c3RhdGVtZW50',
      'c2ln',
    );
  });

  it('refuses a key version that is not a u32 before it reaches the module', async () => {
    const vault = mockVault();
    const { dispatch } = setup([vault]);
    for (const keyVersion of [-1, 1.5, Number.NaN, 2 ** 32]) {
      await expect(
        dispatch('openSpace', [{ spaceId: UUID, keyVersion, sealed: 'c2s' }]),
      ).rejects.toMatchObject({ code: 'invalid' });
      await expect(
        dispatch('confirmationStatement', [
          { space: UUID, member: UUID, memberKeyVersion: keyVersion, fingerprint: 'ZnA' },
        ]),
      ).rejects.toMatchObject({ code: 'invalid' });
    }
    expect(vault.openSpace).not.toHaveBeenCalled();
    expect(vault.confirmationStatement).not.toHaveBeenCalled();
  });

  it('keeps a released emergency key behind a handle and opens items with it', async () => {
    const vault = mockVault();
    const { dispatch } = setup([vault]);
    const handle = await dispatch('openEmergencyKey', ['c2VhbGVk']);
    expect(handle).toBe(21);
    const json = await dispatch('openEmergencyItem', [
      handle,
      { id: UUID, owner: `user:${UUID}`, kind: 'login', revision: 3, ciphertext: 'Y3Q', itemKey: 'aw' },
    ]);
    expect(json).toBe('{"name":"bank"}');
    expect(vault.openEmergencyItem).toHaveBeenCalledWith(
      21,
      UUID,
      `user:${UUID}`,
      'login',
      3n,
      'Y3Q',
      'aw',
      undefined,
    );
    await dispatch('release', [handle]);
    expect(vault.release).toHaveBeenCalledWith(21);
  });

  it('makes spaces and collections and parses what the vault returns', async () => {
    const vault = mockVault();
    const { dispatch } = setup([vault]);
    const made = await dispatch('newSpace', [
      { spaceId: UUID, collectionId: UUID, spaceName: 'Family', collectionName: 'Everyone' },
    ]);
    expect(made.collection.sealedKey).toBe('Y29sbC1rZXk');
    expect(vault.newSpace).toHaveBeenCalledWith(UUID, UUID, 'Family', 'Everyone');
    expect(await dispatch('newCollection', [{ spaceId: UUID, collectionId: UUID, name: 'Private' }])).toEqual({
      name: 'bmFtZQ',
      sealedKey: 'a2V5',
    });

    await dispatch('openSpace', [{ spaceId: UUID, keyVersion: 1, sealed: 'c2s' }]);
    expect(vault.openSpace).toHaveBeenCalledWith(UUID, 1, 'c2s');
    await dispatch('openCollection', [{ spaceId: UUID, collectionId: UUID, keyVersion: 2, sealed: 'Y2s' }]);
    expect(vault.openCollection).toHaveBeenCalledWith(UUID, UUID, 2, 'Y2s');

    const address = { spaceId: UUID, keyVersion: 1, kind: 'space' as const, id: UUID };
    expect(await dispatch('openName', [{ ...address, ciphertext: 'Y3Q' }])).toBe('Family');
    expect(vault.openName).toHaveBeenCalledWith(UUID, 1, 'space', UUID, 'Y3Q');
    expect(await dispatch('sealName', [{ ...address, name: 'Family' }])).toBe('c2VhbGVk');
    expect(vault.sealName).toHaveBeenCalledWith(UUID, 1, 'space', UUID, 'Family');

    await dispatch('sealSpaceKeyTo', [{ spaceId: UUID, recipientKx1: 'a3g', recipientId: 'aWQ' }]);
    expect(vault.sealSpaceKeyTo).toHaveBeenCalledWith(UUID, 'a3g', 'aWQ');
    await dispatch('sealCollectionKeyTo', [
      { spaceId: UUID, collectionId: UUID, recipientKx1: 'a3g', recipientId: 'aWQ' },
    ]);
    expect(vault.sealCollectionKeyTo).toHaveBeenCalledWith(UUID, UUID, 'a3g', 'aWQ');
  });

  it('answers a vault failure on a sharing operation with its code and nothing else', async () => {
    const vault = mockVault({
      sealRootKey: vi.fn(() => {
        throw new Error('locked');
      }),
      openName: vi.fn(() => {
        throw new Error('anything');
      }),
    });
    const { dispatch } = setup([vault]);
    await expect(dispatch('sealRootKey', ['a2V5', 'emergency-access', 'YWFk'])).rejects.toBeInstanceOf(Error);
    const codes: string[] = [];
    for (const call of [
      () => dispatch('sealRootKey', ['a2V5', 'emergency-access', 'YWFk']),
      () =>
        dispatch('openName', [{ spaceId: UUID, keyVersion: 1, kind: 'space', id: UUID, ciphertext: 'Y3Q' }]),
    ]) {
      try {
        await call();
      } catch (error) {
        codes.push(codeOf(error));
      }
    }
    expect(codes).toEqual(['locked', 'invalid']);
  });

  it('makes an account with no password, and seals the root key for this device without returning it', async () => {
    const vault = mockVault();
    const wrap = {
      seal: vi.fn(async () => new Uint8Array([1, 2, 3])),
      open: vi.fn(async () => new Uint8Array([9, 9])),
      reset: vi.fn(async () => undefined),
    };
    const dispatch = createDispatcher({ loadWasm: async () => () => vault, dpop: dpopStub(), deviceWrap: wrap });

    const account = await dispatch('newSsoAccount', [UUID]);
    expect(account).toMatchObject({ wrappedRootKey: '', keyVersion: 1 });

    const sealed = await dispatch('deviceCopySeal', [UUID, UUID, 1]);
    expect(sealed).toBe('AQID');
    expect(wrap.seal).toHaveBeenCalledWith(expect.any(Uint8Array), UUID, UUID, 1);
    const root = (wrap.seal.mock.calls[0] as unknown as [Uint8Array])[0];
    expect([...root], 'the root key is wiped after use').toEqual([0, 0, 0, 0]);

    const handle = await dispatch('deviceCopyOpen', [UUID, UUID, 1, 'AQID']);
    expect(handle).toBe(34);
    expect(vault.importRoot).toHaveBeenCalledWith('CQk');
    await dispatch('deviceCopyReset', []);
    expect(wrap.reset).toHaveBeenCalled();
  });

  it("seals a tab's root key and session under that tab's own wrap, and leaves the device key alone", async () => {
    const vault = mockVault();
    const device = {
      seal: vi.fn(async () => new Uint8Array([1])),
      open: vi.fn(async () => new Uint8Array([2])),
      reset: vi.fn(async () => undefined),
    };
    const tab = {
      seal: vi.fn(async () => new Uint8Array([1, 2, 3])),
      open: vi.fn(async () => new Uint8Array([9, 9])),
      reset: vi.fn(async () => undefined),
    };
    const tabWrap = vi.fn(() => tab);
    const dispatch = createDispatcher({ loadWasm: async () => () => vault, dpop: dpopStub(), deviceWrap: device, tabWrap });
    await dispatch('newSsoAccount', [UUID]);

    expect(await dispatch('deviceCopySeal', [UUID, UUID, 1, 'tab-1'])).toBe('AQID');
    expect(tabWrap).toHaveBeenLastCalledWith('tab-1', 'root');
    expect(tab.seal).toHaveBeenCalledWith(expect.any(Uint8Array), UUID, UUID, 1);
    expect(await dispatch('deviceCopyOpen', [UUID, UUID, 1, 'AQID', 'tab-1'])).toBe(34);
    expect(tab.open).toHaveBeenCalled();
    await dispatch('deviceCopyReset', ['tab-1']);
    expect(tab.reset).toHaveBeenCalled();

    // The session's tokens go under the same tab, as a separate purpose and with no vault needed.
    expect(await dispatch('tabSeal', ['tab-1', UUID, UUID, 'dG9rZW5z'])).toBe('AQID');
    expect(tabWrap).toHaveBeenLastCalledWith('tab-1', 'session');
    expect(await dispatch('tabOpen', ['tab-1', UUID, UUID, 'AQID'])).toBe('CQk');

    expect(device.seal).not.toHaveBeenCalled();
    expect(device.open).not.toHaveBeenCalled();
    expect(device.reset).not.toHaveBeenCalled();
  });

  it('has no tab copy without a tab key store', async () => {
    const { dispatch } = setup();
    await expect(dispatch('tabSeal', ['tab-1', UUID, UUID, 'AQID'])).rejects.toMatchObject({ code: 'unavailable' });
    await expect(dispatch('deviceCopyReset', ['tab-1'])).rejects.toMatchObject({ code: 'unavailable' });
  });

  it('has no device copy without a device key', async () => {
    const { dispatch } = setup();
    await expect(dispatch('deviceCopySeal', [UUID, UUID, 1])).rejects.toMatchObject({ code: 'unavailable' });
  });

  it('wraps the root key under a passkey, and opens the wrap into a handle that unlocks', async () => {
    const vault = mockVault();
    const { dispatch } = setup([vault]);
    const wrap = await dispatch('prfWrapRoot', ['cHJm', 'Y3JlZA']);
    expect(wrap).toEqual({ wrappedKey: 'd3JhcA', keyVersion: 3 });
    expect(vault.prfWrapRoot).toHaveBeenCalledWith('cHJm', 'Y3JlZA');

    const root = await dispatch('prfOpenRoot', ['cHJm', 'Y3JlZA', UUID, 3, 'd3JhcA']);
    expect(root).toBe(33);
    expect(vault.prfOpenRoot).toHaveBeenCalledWith('cHJm', 'Y3JlZA', UUID, 3, 'd3JhcA');
    await dispatch('unlockWithRoot', [UUID, root, { keyVersion: 3 }]);
    expect(vault.unlockWithRoot).toHaveBeenCalledWith(UUID, 33, 3, undefined, undefined);
  });

  it('makes a Recovery Kit in the worker and opens its wrap with pieces into a handle', async () => {
    const vault = mockVault();
    const { dispatch } = setup([vault]);
    expect(await dispatch('kitMake', [])).toEqual({
      kitId: 'ABCDEFGH',
      pieces: ['p1', 'p2', 'p3'],
      wrappedKey: 'd3JhcA',
      keyVersion: 3,
    });
    expect(await dispatch('kitReadPiece', ['bad'])).toEqual({ problem: 'checksum' });
    expect(await dispatch('kitCheckPieces', [['a', 'a']])).toEqual({ problem: 'duplicate' });
    expect(vault.kitCheckPieces).toHaveBeenCalledWith(JSON.stringify(['a', 'a']));
    const root = await dispatch('kitOpenRoot', [['p1', 'p2'], 'ABCDEFGH', UUID, 3, 'd3JhcA']);
    expect(root).toBe(35);
    expect(vault.kitOpenRoot).toHaveBeenCalledWith(
      JSON.stringify(['p1', 'p2']),
      'ABCDEFGH',
      UUID,
      3,
      'd3JhcA',
    );
  });

  it('opens an approved root key under the request it was sealed for, then unlocks with it', async () => {
    const vault = mockVault();
    const { dispatch } = setup([vault]);
    const made = await dispatch('newDeviceKey', []);
    expect(made).toEqual({ handle: 31, publicKey: 'cHVi' });

    const root = await dispatch('openApprovedKey', [made.handle, UUID, UUID, 'c2VhbGVk']);
    expect(root).toBe(32);
    expect(vault.openApprovedKey).toHaveBeenCalledWith(31, UUID, UUID, 'c2VhbGVk');

    await dispatch('unlockWithRoot', [UUID, root, { keyVersion: 4, sealedPrivateKeys: 'c2s' }]);
    expect(vault.unlockWithRoot).toHaveBeenCalledWith(UUID, 32, 4, 'c2s', undefined);
    await dispatch('unlockWithRoot', [UUID, root]);
    expect(vault.unlockWithRoot).toHaveBeenLastCalledWith(UUID, 32, 1, undefined, undefined);
    // The bundle the new device must check the opened keys against goes through as it is.
    await dispatch('unlockWithRoot', [
      UUID,
      root,
      { keyVersion: 4, sealedPrivateKeys: 'c2s', publicBundle: 'YnVuZGxl' },
    ]);
    expect(vault.unlockWithRoot).toHaveBeenLastCalledWith(UUID, 32, 4, 'c2s', 'YnVuZGxl');
  });

  it('answers a box that does not open with invalid and nothing else', async () => {
    const vault = mockVault({
      openApprovedKey: vi.fn(() => {
        throw new Error('invalid');
      }),
    });
    const { dispatch } = setup([vault]);
    await expect(
      dispatch('openApprovedKey', [31 as never, UUID, UUID, 'c2VhbGVk']),
    ).rejects.toThrow('invalid');
  });

  it('seals and opens an item of a space collection, with the collection key version', async () => {
    const vault = mockVault();
    const { dispatch } = setup([vault]);
    const sealed = await dispatch('sealSpaceItem', [
      { spaceId: UUID, collectionId: UUID, id: UUID, kind: 'login', revision: 3, json: '{"name":"vpn"}' },
    ]);
    expect(sealed).toEqual({ ciphertext: 'c2k', itemKey: 'a2s', keyVersion: 2 });
    expect(vault.sealSpaceItem).toHaveBeenCalledWith(UUID, UUID, UUID, 'login', 3n, '{"name":"vpn"}');

    const json = await dispatch('openSpaceItem', [
      {
        spaceId: UUID,
        collectionId: UUID,
        id: UUID,
        kind: 'login',
        revision: 3,
        keyVersion: 2,
        ciphertext: 'c2k',
        itemKey: 'a2s',
      },
    ]);
    expect(json).toBe('{"name":"vpn"}');
    expect(vault.openSpaceItem).toHaveBeenCalledWith(UUID, UUID, UUID, 'login', 3n, 'c2k', 'a2s', 2);
  });

  it('signs and checks manifests in the module, with the manifest and signature as they are', async () => {
    const vault = mockVault();
    const { dispatch } = setup([vault]);
    expect(await dispatch('manifestSign', ['bWFuaWZlc3Q'])).toBe('c2lnbmF0dXJl');
    expect(vault.manifestSign).toHaveBeenCalledWith('bWFuaWZlc3Q');
    expect(await dispatch('manifestVerifyOwn', ['bWFuaWZlc3Q', 'c2ln'])).toBe(true);
    expect(vault.manifestVerifyOwn).toHaveBeenCalledWith('bWFuaWZlc3Q', 'c2ln');
    expect(await dispatch('manifestVerify', ['YnVuZGxl', 'bWFuaWZlc3Q', 'c2ln'])).toBe(true);
    expect(vault.manifestVerify).toHaveBeenCalledWith('YnVuZGxl', 'bWFuaWZlc3Q', 'c2ln');
  });

  it('refuses a revision or collection key version the module cannot take', async () => {
    const vault = mockVault();
    const { dispatch } = setup([vault]);
    await expect(
      dispatch('sealSpaceItem', [
        { spaceId: UUID, collectionId: UUID, id: UUID, kind: 'login', revision: -1, json: '{}' },
      ]),
    ).rejects.toMatchObject({ code: 'invalid' });
    await expect(
      dispatch('openSpaceItem', [
        {
          spaceId: UUID,
          collectionId: UUID,
          id: UUID,
          kind: 'login',
          revision: 1,
          keyVersion: 1.5,
          ciphertext: 'c2k',
          itemKey: 'a2s',
        },
      ]),
    ).rejects.toMatchObject({ code: 'invalid' });
    expect(vault.sealSpaceItem).not.toHaveBeenCalled();
    expect(vault.openSpaceItem).not.toHaveBeenCalled();
  });

  it('defaults the TOTP issuer and account', async () => {
    const vault = mockVault();
    const { dispatch } = setup([vault]);
    const enrolment = await dispatch('totpUri', []);
    expect(enrolment.secret).toBe('JBSWY3DPEHPK3PXP');
    expect(vault.totpEnrol).toHaveBeenLastCalledWith(undefined, 'Kemlock', 'account');
    await dispatch('totpUri', ['JBSWY3DPEHPK3PXP', { issuer: 'Acme', account: 'a@b.co' }]);
    expect(vault.totpEnrol).toHaveBeenLastCalledWith('JBSWY3DPEHPK3PXP', 'Acme', 'a@b.co');
  });

  it('hands DPoP to the signer without touching the vault', async () => {
    const { dispatch, dpop, loadWasm } = setup();
    expect(await dispatch('dpopProof', ['POST', 'https://x.test/a?b=c', 'n', 'tok'])).toBe('proof');
    expect(dpop.proof).toHaveBeenCalledWith('POST', 'https://x.test/a?b=c', 'n', 'tok');
    await dispatch('dpopReset', []);
    expect(dpop.reset).toHaveBeenCalled();
    expect(loadWasm).not.toHaveBeenCalled();
  });

  it('lock wipes the vault, frees it and starts the next operation on a fresh one', async () => {
    const first = mockVault();
    const second = mockVault();
    const { dispatch, factory } = setup([first, second]);
    await dispatch('opaqueLoginStart', [7 as never]);
    await dispatch('lock', []);
    expect(first.lock).toHaveBeenCalledTimes(1);
    expect(first.free).toHaveBeenCalledTimes(1);
    await dispatch('opaqueLoginStart', [7 as never]);
    expect(factory).toHaveBeenCalledTimes(2);
    expect(second.opaqueLoginStart).toHaveBeenCalledTimes(1);
    expect(first.opaqueLoginStart).toHaveBeenCalledTimes(1);
  });

  it('lock with nothing open does nothing', async () => {
    const { dispatch, loadWasm } = setup();
    await dispatch('lock', []);
    expect(loadWasm).not.toHaveBeenCalled();
  });

  it('refuses an operation it does not know', async () => {
    const { dispatch } = setup();
    await expect(
      (dispatch as unknown as (op: string, args: unknown[]) => Promise<unknown>)('constructor', []),
    ).rejects.toMatchObject({ code: 'invalid' });
    await expect(
      (dispatch as unknown as (op: string, args: unknown[]) => Promise<unknown>)('nope', []),
    ).rejects.toMatchObject({ code: 'invalid' });
  });
});

describe('error codes', () => {
  it('keeps only the code', () => {
    expect(codeOf(new CryptoError('unavailable'))).toBe('unavailable');
    expect(codeOf(new Error('locked'))).toBe('locked');
    expect(codeOf(new Error('invalid'))).toBe('invalid');
    expect(codeOf(new Error('RuntimeError: unreachable at secret.rs:1'))).toBe('invalid');
    expect(codeOf('a string')).toBe('invalid');
  });
});

class FakeScope implements WorkerScope {
  listener: ((event: { data: unknown }) => void) | undefined;
  sent: WorkerResponse[] = [];
  addEventListener(_type: 'message', listener: (event: { data: unknown }) => void) {
    this.listener = listener;
  }
  postMessage(message: WorkerResponse) {
    this.sent.push(message);
  }
  receive(data: unknown) {
    this.listener?.({ data });
  }
}

const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

describe('attachWorker', () => {
  it('answers a request with its id', async () => {
    const scope = new FakeScope();
    attachWorker(scope, setup().dispatch);
    const request: WorkerRequest<'opaqueLoginStart'> = { id: 5, op: 'opaqueLoginStart', args: [7 as never] };
    scope.receive(request);
    await settle();
    expect(scope.sent).toEqual([{ id: 5, ok: true, result: { state: 10, request: 'bG9naW4' } }]);
  });

  it('answers a failure with a code and nothing else', async () => {
    const scope = new FakeScope();
    const vault = mockVault({
      opaqueLoginStart: vi.fn(() => {
        throw new Error('locked');
      }),
    });
    attachWorker(scope, setup([vault]).dispatch);
    scope.receive({ id: 1, op: 'opaqueLoginStart', args: [7] });
    await settle();
    expect(scope.sent).toEqual([{ id: 1, ok: false, code: 'locked' }]);
  });

  it('ignores messages that are not requests', async () => {
    const scope = new FakeScope();
    attachWorker(scope, setup().dispatch);
    for (const junk of [null, 'x', 4, {}, { id: 1 }, { id: 1, op: 'lock' }, { id: 'a', op: 'lock', args: [] }]) {
      scope.receive(junk);
    }
    await settle();
    expect(scope.sent).toEqual([]);
  });

  it('serves requests one at a time, in order', async () => {
    const scope = new FakeScope();
    const log: string[] = [];
    let release: (() => void) | undefined;
    const dispatch = vi.fn(async (op: string) => {
      log.push(`start ${op}`);
      if (op === 'unlock') await new Promise<void>((resolve) => (release = resolve));
      log.push(`end ${op}`);
      return undefined;
    });
    attachWorker(scope, dispatch as never);
    scope.receive({ id: 1, op: 'unlock', args: [] });
    scope.receive({ id: 2, op: 'lock', args: [] });
    await settle();
    expect(log).toEqual(['start unlock']);
    release?.();
    await settle();
    expect(log).toEqual(['start unlock', 'end unlock', 'start lock', 'end lock']);
    expect(scope.sent.map((m) => m.id)).toEqual([1, 2]);
  });
});
