import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { ItemDto } from '@/api/types';
import { signedItem } from '@/api/signedWrites';
import { encodeB64, utf8 } from '@/lib/b64url';
import { memoryBundlePinStore } from '@/spaces/anchors';
import { crypto, fakeBundleOf, resetFakeCrypto, setFakeKeyVersion } from '@/test/fake-crypto';
import { createBundleHistory } from './bundleHistory';
import { createWriteChecker } from './writes';

const ACCOUNT = '99999999-9999-4999-8999-999999999999';
const MEMBER = '55555555-5555-4555-8555-555555555555';
const OWN = `user:${ACCOUNT}`;
const SPACE_ID = '44444444-4444-4444-8444-444444444444';
const SPACE = `space:${SPACE_ID}`;
const A = '11111111-1111-4111-8111-111111111111';

const item = (owner: string, revision = 2, extra: Partial<ItemDto> = {}): ItemDto => ({
  id: A,
  owner,
  kind: 'login',
  format: 'kem1',
  revision,
  keyVersion: 1,
  ciphertext: 'Y2lwaGVy',
  itemKey: 'a2V5',
  deleted: false,
  ...(owner === SPACE ? { collectionId: '33333333-3333-4333-8333-333333333333' } : {}),
  ...extra,
});

const spaceSigner = vi.fn(async (_space: string, signer: string) =>
  signer === MEMBER ? fakeBundleOf(MEMBER, 1) : null,
);

function checker(account: string | null = ACCOUNT) {
  return createWriteChecker({ crypto, accountId: () => account, spaceSigner });
}

beforeEach(async () => {
  resetFakeCrypto();
  spaceSigner.mockClear();
  await crypto.unlock(ACCOUNT, utf8(`wrapped:${ACCOUNT}`), new Uint8Array(), new Uint8Array());
});

describe('the verdict on a write signature', () => {
  it('has none for an item that is not kem1', async () => {
    expect(await checker().verdict({ ...item(OWN), format: 'bw' })).toBeUndefined();
  });

  it('is unsigned for an item that carries no signature', async () => {
    expect(await checker().verdict(item(OWN))).toBe('unsigned');
  });

  it('is signed for the account its own write, and invalid once anything it covers changes', async () => {
    const signed = await signedItem(crypto, item(OWN, 3));
    expect(await checker().verdict(signed)).toBe('signed');
    expect(await checker().verdict({ ...signed, revision: 4 })).toBe('invalid');
    expect(await checker().verdict({ ...signed, ciphertext: 'b3RoZXI' })).toBe('invalid');
    expect(await checker().verdict({ ...signed, deleted: true, ciphertext: null, itemKey: null })).toBe('invalid');
  });

  it('is signed for a signed deletion', async () => {
    const tombstone = await signedItem(crypto, { ...item(OWN, 5), deleted: true, ciphertext: null, itemKey: null });
    expect(tombstone.deleted).toBe(true);
    expect(await checker().verdict(tombstone)).toBe('signed');
  });

  it('is invalid for a signature that is partial, or names another account for the own vault', async () => {
    const signed = await signedItem(crypto, item(OWN));
    expect(await checker().verdict({ ...signed, writerKeyVersion: null })).toBe('invalid');
    expect(await checker().verdict({ ...signed, writer: MEMBER })).toBe('invalid');
    expect(await checker().verdict({ ...signed, writeSignature: null })).toBe('invalid');
  });

  it('is unknown when the vault is locked or the account is another', async () => {
    const signed = await signedItem(crypto, item(OWN));
    expect(await checker(MEMBER).verdict(signed)).toBe('unknown');
    resetFakeCrypto();
    expect(await checker().verdict(signed)).toBe('unknown');
  });

  it('checks a space item against the bundle of a member the space vouches for', async () => {
    // A member signs on their own device: the fake worker signs as the account it was opened for.
    resetFakeCrypto();
    await crypto.unlock(MEMBER, utf8(`wrapped:${MEMBER}`), new Uint8Array(), new Uint8Array());
    const signed = await signedItem(crypto, item(SPACE));
    // This browser is the account's, and checks with the member's bundle.
    resetFakeCrypto();
    await crypto.unlock(ACCOUNT, utf8(`wrapped:${ACCOUNT}`), new Uint8Array(), new Uint8Array());
    expect(await checker().verdict(signed)).toBe('signed');
    expect(spaceSigner).toHaveBeenCalledWith(SPACE_ID, MEMBER, { former: true });
    expect(await checker().verdict({ ...signed, revision: 9 })).toBe('invalid');
  });

  it('is unknown for a space writer the space does not vouch for', async () => {
    const signed = await signedItem(crypto, item(SPACE));
    expect(signed.writer).toBe(ACCOUNT);
    expect(await checker().verdict(signed)).toBe('unknown');
  });

  it('is unknown when the member list cannot be reached', async () => {
    spaceSigner.mockRejectedValueOnce(new Error('offline'));
    const signed = await signedItem(crypto, item(SPACE, 2, { writer: MEMBER, writerKeyVersion: 1, writeSignature: 'c2ln' }));
    expect(await checker().verdict(signed)).toBe('unknown');
  });
});

describe("a space member's past bundle", () => {
  it("is not pinned from a member list that is only the server's word", async () => {
    resetFakeCrypto();
    await crypto.unlock(MEMBER, utf8(`wrapped:${MEMBER}`), new Uint8Array(), new Uint8Array());
    const signed = await signedItem(crypto, item(SPACE));
    resetFakeCrypto();
    await crypto.unlock(ACCOUNT, utf8(`wrapped:${ACCOUNT}`), new Uint8Array(), new Uint8Array());
    let memberVersion = 1;
    const signer = vi.fn(async (_space: string, writer: string) =>
      writer === MEMBER ? fakeBundleOf(MEMBER, memberVersion) : null,
    );
    const pins = memoryBundlePinStore();
    const history = createBundleHistory({
      api: {
        at: async () => ({
          keyVersion: 1,
          publicBundle: encodeB64(fakeBundleOf(MEMBER, 1)),
          bundleSignature: encodeB64(utf8('sig')),
        }),
      },
      crypto,
      accountId: () => ACCOUNT,
      pins,
    });
    const check = createWriteChecker({ crypto, accountId: () => ACCOUNT, spaceSigner: signer, history });
    expect(await check.verdict(signed)).toBe('signed');
    expect(await pins.load(ACCOUNT, MEMBER, 1)).toBeUndefined();
    // Once the member has moved on, a past version nothing vouched has no verdict.
    memberVersion = 2;
    check.beginSync();
    expect(await check.verdict(signed)).toBe('unknown');
  });
});

describe('what a sync looks up', () => {
  const signedBy = async () => {
    resetFakeCrypto();
    await crypto.unlock(MEMBER, utf8(`wrapped:${MEMBER}`), new Uint8Array(), new Uint8Array());
    const signed = await signedItem(crypto, item(SPACE));
    resetFakeCrypto();
    await crypto.unlock(ACCOUNT, utf8(`wrapped:${ACCOUNT}`), new Uint8Array(), new Uint8Array());
    return signed;
  };

  it("asks for a space's writer once for all the items of a sync, and again for the next", async () => {
    const signed = await signedBy();
    const check = checker();
    check.beginSync();
    spaceSigner.mockClear();
    for (let n = 0; n < 5; n += 1) expect(await check.verdict(signed)).toBe('signed');
    expect(spaceSigner).toHaveBeenCalledTimes(1);
    check.beginSync();
    expect(await check.verdict(signed)).toBe('signed');
    expect(spaceSigner).toHaveBeenCalledTimes(2);
  });

  it('does not keep a failure, and forgets an answer after a while without a sync', async () => {
    const signed = await signedBy();
    let time = 0;
    const check = createWriteChecker({ crypto, accountId: () => ACCOUNT, spaceSigner, now: () => time });
    spaceSigner.mockClear();
    spaceSigner.mockRejectedValueOnce(new Error('offline'));
    expect(await check.verdict(signed)).toBe('unknown');
    expect(await check.verdict(signed)).toBe('signed');
    expect(spaceSigner).toHaveBeenCalledTimes(2);
    expect(await check.verdict(signed)).toBe('signed');
    expect(spaceSigner).toHaveBeenCalledTimes(2);
    time = 60_000;
    expect(await check.verdict(signed)).toBe('signed');
    expect(spaceSigner).toHaveBeenCalledTimes(3);
  });
});

describe('a write signed under a key version the writer has replaced', () => {
  const served = (bundle: Uint8Array) => ({
    keyVersion: 1,
    publicBundle: encodeB64(bundle),
    bundleSignature: encodeB64(utf8('sig')),
  });

  /** The fake worker, saying which bundle is the account's own at the version it is unlocked at. */
  function ownWorker(version: () => number) {
    return { ...crypto, ownFingerprint: async () => crypto.fingerprint(fakeBundleOf(ACCOUNT, version())) };
  }

  it('is checked against the pinned bundle of that version, for the account itself', async () => {
    let current = 1;
    const worker = ownWorker(() => current);
    const history = createBundleHistory({
      api: { at: async (_account, version) => (version === 1 ? served(fakeBundleOf(ACCOUNT, 1)) : null) },
      crypto: worker,
      accountId: () => ACCOUNT,
      pins: memoryBundlePinStore(),
    });
    const check = createWriteChecker({ crypto: worker, accountId: () => ACCOUNT, spaceSigner, history });

    // Signed while its keys were at version 1, and checked then: the browser pins that bundle.
    const before = await signedItem(worker, item(OWN, 3));
    expect(before.writerKeyVersion).toBe(1);
    expect(await check.verdict(before)).toBe('signed');

    // The account replaces its keys. What it signed before still verifies, and a forgery doesn't.
    setFakeKeyVersion(2);
    current = 2;
    expect(await check.verdict(before)).toBe('signed');
    expect(await check.verdict({ ...before, revision: 9 })).toBe('invalid');
    // A write at the new version is checked with the account's own key, and one at a version
    // beyond it is no verdict.
    const after = await signedItem(worker, item(OWN, 4));
    expect(after.writerKeyVersion).toBe(2);
    expect(await check.verdict(after)).toBe('signed');
    expect(await check.verdict({ ...after, writerKeyVersion: 3 })).toBe('unknown');
  });

  it('has no verdict in a browser that never saw that version vouched', async () => {
    let current = 1;
    const worker = ownWorker(() => current);
    const before = await signedItem(worker, item(OWN, 3));
    setFakeKeyVersion(2);
    current = 2;
    const history = createBundleHistory({
      api: { at: async () => served(fakeBundleOf(ACCOUNT, 1)) },
      crypto: worker,
      accountId: () => ACCOUNT,
      pins: memoryBundlePinStore(),
    });
    const check = createWriteChecker({ crypto: worker, accountId: () => ACCOUNT, spaceSigner, history });
    expect(await check.verdict(before)).toBe('unknown');
    // And without a history at all.
    const bare = createWriteChecker({ crypto: worker, accountId: () => ACCOUNT, spaceSigner });
    expect(await bare.verdict(before)).toBe('unknown');
  });

  it('is checked against the member\'s pinned bundle of that version in a space', async () => {
    // The member signs on their own device, at key version 1.
    resetFakeCrypto();
    await crypto.unlock(MEMBER, utf8(`wrapped:${MEMBER}`), new Uint8Array(), new Uint8Array());
    const signed = await signedItem(crypto, item(SPACE));
    expect(signed.writerKeyVersion).toBe(1);
    resetFakeCrypto();
    await crypto.unlock(ACCOUNT, utf8(`wrapped:${ACCOUNT}`), new Uint8Array(), new Uint8Array());

    let memberVersion = 1;
    const signer = Object.assign(
      vi.fn(async (_space: string, writer: string) =>
        writer === MEMBER ? fakeBundleOf(MEMBER, memberVersion) : null,
      ),
      { vouched: true },
    );
    const history = createBundleHistory({
      api: { at: async (_account, version) => (version === 1 ? served(fakeBundleOf(MEMBER, 1)) : null) },
      crypto,
      accountId: () => ACCOUNT,
      pins: memoryBundlePinStore(),
    });
    const check = createWriteChecker({ crypto, accountId: () => ACCOUNT, spaceSigner: signer, history });
    expect(await check.verdict(signed)).toBe('signed');

    // The member rotates: the space vouches for their version 2 bundle now.
    memberVersion = 2;
    check.beginSync();
    expect(await check.verdict(signed)).toBe('signed');
    expect(await check.verdict({ ...signed, revision: 9 })).toBe('invalid');
    expect(await check.verdict({ ...signed, writerKeyVersion: 3 })).toBe('unknown');
  });
});
