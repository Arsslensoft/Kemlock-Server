// @vitest-environment node
// The page's adapters over the crypto worker: bytes in and out, base64url across, and nothing
// else changed on the way.
import { describe, expect, it, vi } from 'vitest';

import { CryptoError } from '@/crypto/types';
import { decodeB64, encodeB64, fromUtf8, utf8 } from '@/lib/b64url';
import { createSpaceCrypto } from '@/spaces/crypto';
import { createSharingCrypto, isUnavailable } from './crypto';

const SPACE = '00010203-0405-0607-0809-0a0b0c0d0e0f';
const COLLECTION = '10111213-1415-1617-1819-1a1b1c1d1e1f';

function worker() {
  return {
    sealRootKey: vi.fn(async (_kx: string, _context: string, _aad: string) => encodeB64(utf8('root-box'))),
    sealEmergencyKey: vi.fn(async (_bundle: string, _signature: string, _grantee: string) => encodeB64(utf8('emergency-box'))),
    signStatement: vi.fn(async (_statement: string, _context: string) => encodeB64(utf8('signature'))),
    newSpace: vi.fn(async () => ({
      name: encodeB64(utf8('name')),
      sealedSpaceKey: encodeB64(utf8('space-key')),
      sealedSpaceKeySignature: encodeB64(utf8('space-sig')),
      collection: {
        name: encodeB64(utf8('coll')),
        sealedKey: encodeB64(utf8('coll-key')),
        sealedKeySignature: encodeB64(utf8('coll-sig')),
      },
    })),
    openSpace: vi.fn(async () => undefined),
    openCollection: vi.fn(async () => undefined),
    openName: vi.fn(async () => 'Family'),
    sealName: vi.fn(async () => encodeB64(utf8('sealed-name'))),
    newCollection: vi.fn(async () => ({
      name: encodeB64(utf8('coll')),
      sealedKey: encodeB64(utf8('coll-key')),
      sealedKeySignature: encodeB64(utf8('coll-sig')),
    })),
    sealSpaceKeyTo: vi.fn(async () => ({
      sealed: encodeB64(utf8('space-box')),
      signature: encodeB64(utf8('space-box-sig')),
    })),
    sealCollectionKeyTo: vi.fn(async () => ({
      sealed: encodeB64(utf8('coll-box')),
      signature: encodeB64(utf8('coll-box-sig')),
    })),
    verifyKeyBox: vi.fn(async () => true),
    confirmationStatement: vi.fn(async () => encodeB64(utf8('statement'))),
    verifyBundle: vi.fn(async (_bundle: string, _signature: string) => true),
    ownFingerprint: vi.fn(async () => '11111 22222'),
    verifyConfirmation: vi.fn(async () => true),
    newChainedSpace: vi.fn(async () => ({
      ok: true as const,
      records: [{ entry: 'ZW50cnk', signature: 'c2ln' }],
      seals: [],
      names: [],
    })),
    buildChainRecords: vi.fn(async () => ({
      ok: true as const,
      records: [],
      seals: [],
      names: [],
    })),
    buildKeyReplacement: vi.fn(async () => ({
      ok: true as const,
      records: [],
      seals: [],
      names: [],
    })),
    buildReseal: vi.fn(async () => ({
      ok: true as const,
      records: [],
      seals: [],
      names: [],
    })),
    verifySpaceChain: vi.fn(async () => ({ ok: false as const, reason: 'forked', seq: 3 })),
    spaceChainView: vi.fn(async () => null),
    sealLocal: vi.fn(async () => 'c2VhbGVk'),
    openLocal: vi.fn(async () => 'text'),
    acceptFirstContact: vi.fn(async () => undefined),
    openChainKey: vi.fn(async () => undefined),
  };
}

describe('sharing over the worker', () => {
  it('seals the root key to a key and returns the box as bytes', async () => {
    const api = worker();
    const sharing = createSharingCrypto(api);
    const kx = new Uint8Array(1600).fill(9);
    const aad = new Uint8Array(32).fill(3);
    const box = await sharing.sealRootKey(kx, 'device-approval', aad);
    expect(fromUtf8(box)).toBe('root-box');
    expect(api.sealRootKey).toHaveBeenCalledWith(encodeB64(kx), 'device-approval', encodeB64(aad));
  });

  it('seals the root key to an emergency contact from their bundle, never from a bare key', async () => {
    const api = worker();
    const sharing = createSharingCrypto(api);
    const bundle = new Uint8Array(8).fill(5);
    const signature = new Uint8Array(4).fill(6);
    const grantee = '00010203-0405-0607-0809-0a0b0c0d0e0f';
    expect(fromUtf8(await sharing.sealEmergencyKey(bundle, signature, grantee))).toBe('emergency-box');
    expect(api.sealEmergencyKey).toHaveBeenCalledWith(encodeB64(bundle), encodeB64(signature), grantee);
    expect(api.sealRootKey).not.toHaveBeenCalled();
  });

  it('signs a statement and returns the signature as bytes', async () => {
    const api = worker();
    const sharing = createSharingCrypto(api);
    const signature = await sharing.signStatement(utf8('statement'), 'confirm');
    expect(fromUtf8(signature)).toBe('signature');
    expect(api.signStatement).toHaveBeenCalledWith(encodeB64(utf8('statement')), 'confirm');
  });

  it('is available but says unavailable for the trusted-device copy', async () => {
    const sharing = createSharingCrypto(worker());
    expect(sharing.available).toBe(true);
    expect(sharing.canWrapForThisDevice).toBe(false);
    const failure = await sharing
      .wrapForThisDevice({ accountId: new Uint8Array(16), deviceId: new Uint8Array(16), keyVersion: 1 })
      .catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(CryptoError);
    expect(isUnavailable(failure)).toBe(true);
  });

  it('wraps the root key for this device when the worker has a device key', async () => {
    const deviceCopySeal = vi.fn(async (_a: string, _d: string, _v: number) => encodeB64(utf8('copy')));
    const sharing = createSharingCrypto({ ...worker(), deviceCopySeal });
    expect(sharing.canWrapForThisDevice).toBe(true);
    const copy = await sharing.wrapForThisDevice({
      accountId: Uint8Array.from({ length: 16 }, (_, i) => i),
      deviceId: new Uint8Array(16).fill(0xab),
      keyVersion: 2,
    });
    expect(fromUtf8(copy)).toBe('copy');
    expect(deviceCopySeal).toHaveBeenCalledWith(
      '00010203-0405-0607-0809-0a0b0c0d0e0f',
      'abababab-abab-abab-abab-abababababab',
      2,
    );
  });

  it('lets the worker’s refusal through', async () => {
    const api = worker();
    api.sealRootKey.mockRejectedValueOnce(new CryptoError('locked'));
    await expect(
      createSharingCrypto(api).sealRootKey(new Uint8Array(1600), 'device-approval', new Uint8Array(32)),
    ).rejects.toMatchObject({ code: 'locked' });
  });
});

describe('spaces over the worker', () => {
  it('makes a space and decodes every part', async () => {
    const api = worker();
    const spaces = createSpaceCrypto(api);
    const made = await spaces.newSpace({
      spaceId: SPACE,
      collectionId: COLLECTION,
      spaceName: 'Family',
      collectionName: 'Everyone',
    });
    expect(fromUtf8(made.name)).toBe('name');
    expect(fromUtf8(made.sealedSpaceKey)).toBe('space-key');
    expect(fromUtf8(made.collection.sealedKey)).toBe('coll-key');
    expect(api.newSpace).toHaveBeenCalledWith({
      spaceId: SPACE,
      collectionId: COLLECTION,
      spaceName: 'Family',
      collectionName: 'Everyone',
    });
  });

  it('checks a bundle’s own signature and reads my own fingerprint', async () => {
    const api = worker();
    const spaces = createSpaceCrypto(api);
    const bundle = utf8('bundle');
    const signature = utf8('signature');
    await expect(spaces.verifyBundle(bundle, signature)).resolves.toBe(true);
    expect(api.verifyBundle).toHaveBeenCalledWith(encodeB64(bundle), encodeB64(signature));
    await expect(spaces.ownFingerprint()).resolves.toBe('11111 22222');
  });

  it('passes the chain through, with a key box as bytes', async () => {
    const api = worker();
    const spaces = createSpaceCrypto(api);
    const records = [{ entry: 'ZW50cnk', signature: 'c2ln' }];
    await expect(spaces.verifySpaceChain({ spaceId: SPACE, records })).resolves.toEqual({
      ok: false,
      reason: 'forked',
      seq: 3,
    });
    expect(api.verifySpaceChain).toHaveBeenCalledWith({ spaceId: SPACE, records });
    await expect(spaces.spaceChainView(SPACE)).resolves.toBeNull();
    const input = { spaceId: SPACE, collectionId: COLLECTION, spaceName: 'Family', collectionName: 'Everyone', at: 5 };
    await expect(spaces.newChainedSpace(input)).resolves.toMatchObject({ records: [{ entry: 'ZW50cnk' }] });
    expect(api.newChainedSpace).toHaveBeenCalledWith(input);
    const build = { spaceId: SPACE, at: 5, change: { action: 'seal' as const } };
    await expect(spaces.buildChainRecords(build)).resolves.toMatchObject({ ok: true, records: [] });
    expect(api.buildChainRecords).toHaveBeenCalledWith(build);
    const replacing = { spaceId: SPACE, at: 5, replacement: { items: [], names: [] } };
    await expect(spaces.buildKeyReplacement(replacing)).resolves.toMatchObject({ ok: true });
    expect(api.buildKeyReplacement).toHaveBeenCalledWith(replacing);
    await expect(spaces.buildReseal({ spaceId: SPACE, items: [] })).resolves.toMatchObject({ ok: true });
    expect(api.buildReseal).toHaveBeenCalledWith({ spaceId: SPACE, items: [] });
    await expect(spaces.sealLocal('anchor/x', 'text')).resolves.toBe('c2VhbGVk');
    expect(api.sealLocal).toHaveBeenCalledWith('anchor/x', 'text');
    await expect(spaces.openLocal('anchor/x', 'c2VhbGVk')).resolves.toBe('text');
    await spaces.acceptFirstContact(SPACE);
    expect(api.acceptFirstContact).toHaveBeenCalledWith(SPACE);
    const sealed = utf8('box');
    const list = [{ bundleVersion: 1, key: 'space', member: COLLECTION, sealHash: 'aGFzaA', version: 2 }];
    await spaces.openChainKey({ spaceId: SPACE, key: 'space', servedVersion: 2, sealed, list });
    expect(api.openChainKey).toHaveBeenCalledWith({
      spaceId: SPACE,
      key: 'space',
      servedVersion: 2,
      sealed: encodeB64(sealed),
      list,
    });
  });

  it('opens keys and names from bytes', async () => {
    const api = worker();
    const spaces = createSpaceCrypto(api);
    const sealed = utf8('sealed');
    await spaces.openSpace({ spaceId: SPACE, keyVersion: 2, sealed });
    expect(api.openSpace).toHaveBeenCalledWith({ spaceId: SPACE, keyVersion: 2, sealed: encodeB64(sealed) });
    await spaces.openCollection({ spaceId: SPACE, collectionId: COLLECTION, keyVersion: 1, sealed });
    expect(api.openCollection).toHaveBeenCalledWith({
      spaceId: SPACE,
      collectionId: COLLECTION,
      keyVersion: 1,
      sealed: encodeB64(sealed),
    });
    const name = await spaces.openName({
      spaceId: SPACE,
      keyVersion: 1,
      kind: 'collection',
      id: COLLECTION,
      ciphertext: sealed,
    });
    expect(name).toBe('Family');
    expect(api.openName).toHaveBeenCalledWith({
      spaceId: SPACE,
      keyVersion: 1,
      kind: 'collection',
      id: COLLECTION,
      ciphertext: encodeB64(sealed),
    });
  });

  it('seals names, collections and keys to a member as bytes', async () => {
    const api = worker();
    const spaces = createSpaceCrypto(api);
    const kx = new Uint8Array(1600).fill(5);
    const id = new Uint8Array(16).fill(6);

    expect(
      fromUtf8(await spaces.sealName({ spaceId: SPACE, keyVersion: 1, kind: 'group', id: COLLECTION, name: 'Ops' })),
    ).toBe('sealed-name');
    const collection = await spaces.newCollection({ spaceId: SPACE, collectionId: COLLECTION, name: 'Private' });
    expect(fromUtf8(collection.sealedKey)).toBe('coll-key');
    expect(fromUtf8(collection.sealedKeySignature)).toBe('coll-sig');

    const spaceBox = await spaces.sealSpaceKeyTo({ spaceId: SPACE, recipientKx1: kx, recipientId: id });
    expect(fromUtf8(spaceBox.sealed)).toBe('space-box');
    expect(fromUtf8(spaceBox.signature)).toBe('space-box-sig');
    expect(api.sealSpaceKeyTo).toHaveBeenCalledWith({
      spaceId: SPACE,
      recipientKx1: encodeB64(kx),
      recipientId: encodeB64(id),
    });
    const collectionBox = await spaces.sealCollectionKeyTo({
      spaceId: SPACE,
      collectionId: COLLECTION,
      recipientKx1: kx,
      recipientId: id,
    });
    expect(fromUtf8(collectionBox.sealed)).toBe('coll-box');
    expect(fromUtf8(collectionBox.signature)).toBe('coll-box-sig');

    // A key box signature is checked in the worker against the sealer's bundle, from bytes.
    const bundle = new Uint8Array(7242).fill(3);
    expect(
      await spaces.verifyKeyBox({
        sealerBundle: bundle,
        spaceId: SPACE,
        collectionId: COLLECTION,
        keyVersion: 2,
        recipientId: id,
        sealed: collectionBox.sealed,
        signature: collectionBox.signature,
      }),
    ).toBe(true);
    expect(api.verifyKeyBox).toHaveBeenCalledWith({
      sealerBundle: encodeB64(bundle),
      spaceId: SPACE,
      collectionId: COLLECTION,
      keyVersion: 2,
      recipientId: encodeB64(id),
      sealed: encodeB64(collectionBox.sealed),
      signature: encodeB64(collectionBox.signature),
    });
    expect(api.sealCollectionKeyTo).toHaveBeenCalledWith({
      spaceId: SPACE,
      collectionId: COLLECTION,
      recipientKx1: encodeB64(kx),
      recipientId: encodeB64(id),
    });
  });

  it('builds the confirmation statement in the worker and checks one against a bundle', async () => {
    const api = worker();
    const spaces = createSpaceCrypto(api);
    const fingerprint = new Uint8Array(64).fill(8);
    const statement = await spaces.confirmationStatement({
      space: SPACE,
      member: COLLECTION,
      memberKeyVersion: 2,
      fingerprint,
    });
    expect(fromUtf8(statement)).toBe('statement');
    expect(api.confirmationStatement).toHaveBeenCalledWith({
      space: SPACE,
      member: COLLECTION,
      memberKeyVersion: 2,
      fingerprint: encodeB64(fingerprint),
    });

    const bundle = new Uint8Array(7242).fill(1);
    const signature = new Uint8Array(3373).fill(2);
    expect(
      await spaces.verifyConfirmation({
        space: SPACE,
        member: COLLECTION,
        memberKeyVersion: 2,
        fingerprint,
        confirmerBundle: bundle,
        statement,
        signature,
      }),
    ).toBe(true);
    expect(api.verifyConfirmation).toHaveBeenCalledWith({
      space: SPACE,
      member: COLLECTION,
      memberKeyVersion: 2,
      fingerprint: encodeB64(fingerprint),
      confirmerBundle: encodeB64(bundle),
      statement: encodeB64(statement),
      signature: encodeB64(signature),
    });
  });

  it('carries the sharing operations too', async () => {
    const spaces = createSpaceCrypto(worker());
    expect(spaces.available).toBe(true);
    expect(fromUtf8(await spaces.sealRootKey(new Uint8Array(1600), 'device-approval', new Uint8Array(32)))).toBe(
      'root-box',
    );
    expect(decodeB64(encodeB64(new Uint8Array([1, 2, 3])))).toEqual(new Uint8Array([1, 2, 3]));
  });
});
